// Package model holds ARClient's persisted configuration and the rule model that
// both the xray config generator and the zeptun TOML generator read from.
//
// There is deliberately one source of truth for every value that two generators
// must agree on (notably FakednsPool). A desync there does not fail loudly, it
// silently sends selected traffic out the physical NIC while the UI claims it is
// tunnelled, so sharing a single field is cheaper than reconciling two.
package model

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"
)

// Mode selects which engine carries a flow.
type Mode string

const (
	// ModeFrag sends traffic over a direct socket with xray's finalmask
	// ClientHello fragmentation. Defeats SNI/DPI inspection, keeps the real
	// source IP. Cannot reach destinations whose IP is blocked outright.
	ModeFrag Mode = "frag"

	// ModeTunnel sends traffic through Aether. Reaches IP-level blocks, but
	// the exit is not the local address.
	ModeTunnel Mode = "tunnel"

	// ModeAuto probes direct first and escalates to tunnel only if direct
	// fails. Used for UDP voice, where direct is likely to work and is free.
	ModeAuto Mode = "auto"

	// ModeDirect bypasses the engines entirely.
	ModeDirect Mode = "direct"
)

// Valid reports whether m is a known mode.
func (m Mode) Valid() bool {
	switch m {
	case ModeFrag, ModeTunnel, ModeAuto, ModeDirect:
		return true
	}
	return false
}

// PreservesRealIP reports whether the mode keeps the local source address by
// construction, before any measurement.
//
// Only frag qualifies. tunnel and auto both leave through Aether, so they
// present a foreign exit address. auto is listed as non-preserving because on
// failure it escalates to tunnel; see Rule.MeasuredPreservesRealIP for the
// measured answer.
func (m Mode) PreservesRealIP() bool { return m == ModeFrag }

// Transport restricts a rule to a subset of the IP protocols.
type Transport string

const (
	TransportTCP  Transport = "tcp"
	TransportUDP  Transport = "udp"
	TransportBoth Transport = "both"
)

// Valid reports whether t is a known transport.
func (t Transport) Valid() bool {
	switch t {
	case TransportTCP, TransportUDP, TransportBoth:
		return true
	}
	return false
}

// Networks returns the xray "network" values this transport expands to.
func (t Transport) Networks() []string {
	switch t {
	case TransportTCP:
		return []string{"tcp"}
	case TransportUDP:
		return []string{"udp"}
	default:
		return []string{"tcp", "udp"}
	}
}

// Rule is one user-chosen target and the engine that carries it.
type Rule struct {
	Name      string    `json:"name"`
	Domains   []string  `json:"domains"`
	Mode      Mode      `json:"mode"`
	Transport Transport `json:"transport"`
	Enabled   bool      `json:"enabled"`
	Note      string    `json:"note,omitempty"`

	// AutoEscalated is the persisted resolution of ModeAuto.
	//
	// Auto starts direct, because a working direct path is free and keeps the
	// flow out of the tunnel entirely. A health probe that fails to reach the
	// target directly sets this, and the next generated config routes it to the
	// tunnel. Persisting it matters twice over: the choice survives a restart
	// instead of re-probing, and the UI can show why a rule is tunnelled when
	// the user did not ask for it.
	AutoEscalated bool `json:"autoEscalated,omitempty"`

	// Measurement results, written by health probes and never edited by hand.
	// A zero MeasuredAt means "never probed", which the UI renders differently
	// from "probed and failed".
	MeasuredAt        time.Time `json:"measuredAt,omitempty"`
	MeasuredExitIP    string    `json:"measuredExitIp,omitempty"`
	MeasuredExitISO   string    `json:"measuredExitIso,omitempty"`
	MeasuredLatencyMS int64     `json:"measuredLatencyMs,omitempty"`
	MeasuredPreserves bool      `json:"measuredPreservesRealIp"`
	MeasuredReachable bool      `json:"measuredReachable"`
	MeasuredErr       string    `json:"measuredErr,omitempty"`
}

// HasMeasurement reports whether a probe has ever run for this rule.
func (r Rule) HasMeasurement() bool { return !r.MeasuredAt.IsZero() }

// EffectiveMode resolves ModeAuto to the mode the generator should actually
// emit. Every other mode passes through unchanged.
func (r Rule) EffectiveMode() Mode {
	if r.Mode == ModeAuto {
		if r.AutoEscalated {
			return ModeTunnel
		}
		// Direct, not frag: an unprobed auto rule should not be fragmented.
		// Fragmenting traffic that did not need it only costs throughput and
		// makes the bypass path harder to reason about.
		return ModeDirect
	}
	return r.Mode
}

// Normalize lowercases, trims, de-duplicates and sorts the rule's domains and
// fills in defaults for unset enum fields.
//
// Domain matching in xray is case-insensitive, so folding here keeps the
// generated config stable regardless of how the user typed an entry. It also
// makes generated output byte-stable, which the golden test depends on.
//
// Match-type prefixes ("full:", "regexp:") are deliberately preserved rather
// than stripped. A suffix match and an exact match are not interchangeable, so
// quietly dropping the prefix would widen a deliberately narrow rule into a
// broad one — the kind of change that only surfaces later as "something else
// broke".
func (r *Rule) Normalize() {
	if !r.Transport.Valid() {
		r.Transport = TransportBoth
	}
	if !r.Mode.Valid() {
		r.Mode = ModeFrag
	}
	seen := make(map[string]struct{}, len(r.Domains))
	out := make([]string, 0, len(r.Domains))
	for _, d := range r.Domains {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" {
			continue
		}
		if _, dup := seen[d]; dup {
			continue
		}
		seen[d] = struct{}{}
		out = append(out, d)
	}
	sort.Strings(out)
	r.Domains = out
	r.Name = strings.TrimSpace(r.Name)
}

// Validate reports every problem with the rule rather than the first one, so a
// user fixing a rule sees the whole list at once instead of discovering the
// next problem on each restart.
func (r Rule) Validate() error {
	var problems []string
	if !r.Mode.Valid() {
		problems = append(problems, fmt.Sprintf("unknown mode %q", r.Mode))
	}
	if !r.Transport.Valid() {
		problems = append(problems, fmt.Sprintf("unknown transport %q", r.Transport))
	}
	if r.Mode != ModeDirect && len(r.Domains) == 0 {
		problems = append(problems, "needs at least one domain")
	}
	if len(problems) == 0 {
		return nil
	}
	return fmt.Errorf("rule %q: %s", r.Name, strings.Join(problems, "; "))
}

// Config is the whole persisted application configuration.
type Config struct {
	SchemaVersion int                `json:"schemaVersion"`
	Profile       string             `json:"profile"`
	Profiles      map[string]Profile `json:"profiles"`
	Rules         []Rule             `json:"rules"`

	// FakednsPool is the address range xray answers from for selected domains.
	// The zeptun generator turns this same value into the tunnel's include
	// list, which is what lets selective capture avoid resolving anything.
	FakednsPool string `json:"fakednsPool"`

	// Ports on loopback. MixedPort is xray's mixed (HTTP+SOCKS5) inbound;
	// AetherPort is Aether's SOCKS5 listener. Both default high and are
	// randomised per profile to reduce the chance of colliding with a local
	// proxy. Aether's SOCKS5 has no authentication, so loopback binding is
	// the only thing keeping other local processes out.
	MixedPort  int `json:"mixedPort"`
	AetherPort int `json:"aetherPort"`

	// BlockAds adds the geosite:category-ads-all rule. This is the only
	// consumer of geo data, which is why geo assets are optional.
	BlockAds bool `json:"blockAds"`

	// WithGeo records whether geo assets were staged at build time. Generating
	// geosite/geoip rules without them makes the core fail to start.
	WithGeo bool `json:"withGeo"`
}

// DefaultConfig returns a configuration with a single Discord rule in frag
// mode, matching the rule set ARClient is being built to prove.
func DefaultConfig() *Config {
	c := &Config{
		SchemaVersion: SchemaVersion,
		Profile:       DefaultProfileID,
		Profiles:      DefaultProfiles(),
		FakednsPool:   DefaultFakednsPool,
		MixedPort:     10808,
		AetherPort:    1819,
		BlockAds:      false,
		WithGeo:       false,
	}
	c.Rules = []Rule{
		{
			Name:      "Discord",
			Mode:      ModeFrag,
			Transport: TransportBoth,
			Enabled:   true,
			Domains:   append([]string(nil), DiscordSeedDomains...),
			Note:      "Seed list only; run domain discovery to complete it.",
		},
	}
	return c
}

// SchemaVersion is bumped when the on-disk shape changes incompatibly.
const SchemaVersion = 1

// DefaultFakednsPool is the benchmarking range, chosen because it is reserved
// for exactly this and cannot collide with a real CDN.
const DefaultFakednsPool = "198.18.0.0/15"

// DefaultProfileID selects the fragmentation preset at startup.
const DefaultProfileID = "fragB"

// DiscordSeedDomains is a starting point, not an authoritative list.
//
// A partial Discord list fails quietly: messages work, avatars do not, video
// will not play. internal/discovery replaces this with what Discord actually
// contacts, so treat the seed as a bootstrap only.
var DiscordSeedDomains = []string{
	"discord.com",
	"discordapp.com",
	"discordapp.net",
	"discord.gg",
	"cdn.discordapp.com",
	"media.discordapp.net",
	"images-ext-1.discordapp.net",
	"images-ext-2.discordapp.net",
}

// Normalize canonicalises the whole configuration in place.
func (c *Config) Normalize() {
	if !c.FakednsPoolValid() {
		c.FakednsPool = DefaultFakednsPool
	}
	for i := range c.Rules {
		c.Rules[i].Normalize()
	}
	if _, ok := c.Profiles[c.Profile]; !ok {
		if _, ok := c.Profiles[DefaultProfileID]; ok {
			c.Profile = DefaultProfileID
		}
	}
}

// Validate reports every problem with the configuration, so the UI and the
// selftest can present all of them at once rather than one per run.
func (c *Config) Validate() error {
	var problems []string
	if c.MixedPort < 1 || c.MixedPort > 65535 {
		problems = append(problems, fmt.Sprintf("mixedPort %d out of range", c.MixedPort))
	}
	if c.AetherPort < 1 || c.AetherPort > 65535 {
		problems = append(problems, fmt.Sprintf("aetherPort %d out of range", c.AetherPort))
	}
	if c.MixedPort == c.AetherPort {
		problems = append(problems, "mixedPort and aetherPort must differ")
	}
	if !c.FakednsPoolValid() {
		problems = append(problems, fmt.Sprintf("fakednsPool %q is not a valid CIDR", c.FakednsPool))
	}
	if _, ok := c.Profiles[c.Profile]; !ok {
		problems = append(problems, fmt.Sprintf("profile %q not found", c.Profile))
	}
	for _, r := range c.Rules {
		if err := r.Validate(); err != nil {
			problems = append(problems, err.Error())
		}
	}
	if len(problems) == 0 {
		return nil
	}
	return fmt.Errorf("invalid config:\n  - %s", strings.Join(problems, "\n  - "))
}

// FakednsPoolValid reports whether FakednsPool parses as a prefix.
func (c *Config) FakednsPoolValid() bool {
	_, err := netip.ParsePrefix(c.FakednsPool)
	return err == nil
}

// FakednsPrefix parses FakednsPool.
func (c *Config) FakednsPrefix() (netip.Prefix, error) {
	p, err := netip.ParsePrefix(c.FakednsPool)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("fakednsPool %q: %w", c.FakednsPool, err)
	}
	return p, nil
}

// ActiveProfile returns the selected fragmentation preset.
func (c *Config) ActiveProfile() (Profile, bool) {
	p, ok := c.Profiles[c.Profile]
	return p, ok
}

// EnabledDomains returns the normalised, de-duplicated domains of every enabled
// rule resolving to the given effective mode and transport, sorted for stable
// output.
//
// Matching is on EffectiveMode, so an auto rule lands in exactly one bucket:
// direct while unprobed, tunnel once escalated. That keeps it from appearing in
// both the frag and tunnel rule sets at once.
func (c *Config) EnabledDomains(mode Mode, transport Transport) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, r := range c.Rules {
		if !r.Enabled {
			continue
		}
		if r.EffectiveMode() != mode {
			continue
		}
		if !transportMatches(r.Transport, transport) {
			continue
		}
		for _, d := range r.Domains {
			if _, dup := seen[d]; dup {
				continue
			}
			seen[d] = struct{}{}
			out = append(out, d)
		}
	}
	sort.Strings(out)
	return out
}

// transportMatches reports whether a rule's transport contributes to the
// requested one.
//
// Two cases, and getting either wrong is quiet. A rule that covers both
// protocols must satisfy a request for one of them, or a "both" rule produces no
// domains and the outbound it references is never emitted. And a request for
// "both" must be satisfied by any rule, or a TCP-only rule contributes nothing
// to the union and disappears from the catch-all as well.
func transportMatches(have, want Transport) bool {
	if want == TransportBoth || have == TransportBoth {
		return true
	}
	return have == want
}

// TunnelIncludes returns every domain that must resolve to a fake address so
// the zeptun tunnel captures it.
//
// Direct rules are excluded on purpose, and so are auto rules that have not
// escalated. The value of this list is that unselected traffic never enters the
// tunnel at all; widening it to "everything" would make the tunnel the only
// path and turn a proxy misconfiguration into a total outage.
//
// The result is written to the zeptun config as the tunnel's include list, and
// it must be derived from the same FakednsPool the xray generator uses.
func (c *Config) TunnelIncludes() []string {
	seen := make(map[string]struct{})
	var out []string
	for _, r := range c.Rules {
		if !r.Enabled {
			continue
		}
		switch r.EffectiveMode() {
		case ModeFrag, ModeTunnel:
		default:
			continue
		}
		for _, d := range r.Domains {
			if _, dup := seen[d]; dup {
				continue
			}
			seen[d] = struct{}{}
			out = append(out, d)
		}
	}
	sort.Strings(out)
	return out
}
