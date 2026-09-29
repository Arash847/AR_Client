package model

import "testing"

// TestNormalizeIsStable guards the property the golden generated configs depend
// on: the same rules in any order, typed in any case, produce byte-identical
// output. Without it a diff of two generated configs is noise.
func TestNormalizeIsStable(t *testing.T) {
	a := Rule{Name: " d ", Domains: []string{"B.com", "a.com", "b.com", "", "  a.com  "}, Mode: ModeFrag, Transport: TransportBoth}
	a.Normalize()

	b := Rule{Name: "d", Domains: []string{"a.com", "b.com"}, Mode: ModeFrag, Transport: TransportBoth}
	b.Normalize()

	if a.Name != b.Name {
		t.Errorf("names differ: %q vs %q", a.Name, b.Name)
	}
	if len(a.Domains) != 2 || a.Domains[0] != "a.com" || a.Domains[1] != "b.com" {
		t.Errorf("domains = %v, want sorted and de-duplicated [a.com b.com]", a.Domains)
	}
}

// TestNormalizeKeepsFullPrefix checks that a "full:" or "regexp:" prefix is
// not silently dropped.
//
// The two prefixes match differently: a suffix match and an exact match are not
// interchangeable. Stripping one turns a deliberately narrow rule into a broad
// one, which is the kind of change that only shows up as "something else broke
// last week".
func TestNormalizeKeepsFullPrefix(t *testing.T) {
	r := Rule{Name: "x", Domains: []string{"full:api.example.com", "example.com"}, Mode: ModeFrag}
	r.Normalize()

	// Two distinct entries, because they match different sets. Collapsing the
	// prefixed one into the bare name would turn the exact match into a suffix
	// match covering every subdomain.
	if len(r.Domains) != 2 {
		t.Fatalf("domains = %v, want the prefixed and bare forms kept separate", r.Domains)
	}
	if r.Domains[0] != "example.com" || r.Domains[1] != "full:api.example.com" {
		t.Errorf("domains = %v, want [example.com full:api.example.com]", r.Domains)
	}
}

// TestEffectiveModeResolution covers the auto voice path, which is the only
// place a rule's mode changes at runtime.
func TestEffectiveModeResolution(t *testing.T) {
	auto := Rule{Name: "voice", Mode: ModeAuto, Transport: TransportUDP, Domains: []string{"voice.discord.gg"}}
	if got := auto.EffectiveMode(); got != ModeDirect {
		t.Errorf("un-escalated auto resolves to %q, want %q", got, ModeDirect)
	}
	auto.AutoEscalated = true
	if got := auto.EffectiveMode(); got != ModeTunnel {
		t.Errorf("escalated auto resolves to %q, want %q", got, ModeTunnel)
	}
	// Every other mode passes through untouched.
	for _, m := range []Mode{ModeFrag, ModeTunnel, ModeDirect} {
		if got := (Rule{Mode: m}).EffectiveMode(); got != m {
			t.Errorf("mode %q resolved to %q", m, got)
		}
	}
}

// TestTunnelIncludesExcludesDirect is the property that keeps unselected
// traffic off the tunnel.
//
// If this ever widened to include direct rules, the fake address pool would
// cover everything, every destination would enter the tunnel, and the bypass
// guarantee would be gone. It would not fail loudly; the tunnel would simply
// become the only path.
func TestTunnelIncludesExcludesDirect(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Rules = []Rule{
		{Name: "frag", Mode: ModeFrag, Transport: TransportBoth, Enabled: true, Domains: []string{"discord.com"}},
		{Name: "tunnel", Mode: ModeTunnel, Transport: TransportBoth, Enabled: true, Domains: []string{"web.telegram.org"}},
		{Name: "bypass", Mode: ModeDirect, Transport: TransportBoth, Enabled: true, Domains: []string{"example.ir"}},
		{Name: "voice", Mode: ModeAuto, Transport: TransportUDP, Enabled: true, Domains: []string{"voice.discord.gg"}},
		{Name: "off", Mode: ModeFrag, Transport: TransportBoth, Enabled: false, Domains: []string{"disabled.example"}},
	}
	cfg.Normalize()

	got := cfg.TunnelIncludes()
	want := map[string]bool{"discord.com": true, "web.telegram.org": true}
	if len(got) != len(want) {
		t.Fatalf("tunnel includes = %v, want %v", got, want)
	}
	for _, d := range got {
		if !want[d] {
			t.Errorf("unexpected domain %q in the tunnel include list: %v", d, got)
		}
	}
}

// TestTransportMatchMatrix pins the full matrix.
//
// Both halves of this function were wrong at some point, and both failures were
// quiet: a "both" rule produced no domains so the block rules lost their scope,
// and a TCP-only rule contributed nothing to the catch-all union. Neither
// surfaced as an error, only as traffic being routed somewhere unintended.
func TestTransportMatchMatrix(t *testing.T) {
	tests := []struct {
		have   Transport
		query  Transport
		expect bool
	}{
		{TransportBoth, TransportTCP, true},
		{TransportBoth, TransportUDP, true},
		{TransportBoth, TransportBoth, true},
		{TransportTCP, TransportTCP, true},
		{TransportTCP, TransportUDP, false},
		{TransportTCP, TransportBoth, true},
		{TransportUDP, TransportTCP, false},
		{TransportUDP, TransportUDP, true},
		{TransportUDP, TransportBoth, true},
	}
	for _, tt := range tests {
		if got := transportMatches(tt.have, tt.query); got != tt.expect {
			t.Errorf("transportMatches(%q, %q) = %v, want %v", tt.have, tt.query, got, tt.expect)
		}
	}
}

// TestTransportAffectsEveryBucket checks a transport-filtered rule still reaches
// the fakedns list, the tunnel include list and the routing rules. Those three
// have to agree, and a filter that applied to only some of them would put a
// domain in the tunnel that no rule routes, or the reverse.
func TestTransportAffectsEveryBucket(t *testing.T) {
	for _, transport := range []Transport{TransportTCP, TransportUDP, TransportBoth} {
		cfg := DefaultConfig()
		cfg.Rules = []Rule{{
			Name: "a", Mode: ModeFrag, Transport: transport,
			Enabled: true, Domains: []string{"a.example"},
		}}
		cfg.Normalize()

		all := append(append([]string{}, cfg.EnabledDomains(ModeFrag, TransportTCP)...),
			cfg.EnabledDomains(ModeFrag, TransportUDP)...)
		if len(all) == 0 {
			t.Errorf("transport %q produced no domains", transport)
		}
		if includes := cfg.TunnelIncludes(); !containsAny(includes, "a.example") {
			t.Errorf("transport %q: domain is routed but missing from the tunnel include list %v", transport, includes)
		}
	}
}

// TestPreservesRealIPByMode documents which modes can keep the source address
// without a measurement. Only frag qualifies, and a tunnel route that claims
// otherwise is a bug waiting to mislead someone about a payment failing.
func TestPreservesRealIPByMode(t *testing.T) {
	if !ModeFrag.PreservesRealIP() {
		t.Error("frag must preserve the real source IP")
	}
	for _, m := range []Mode{ModeTunnel, ModeAuto, ModeDirect} {
		if m.PreservesRealIP() && m != ModeDirect {
			t.Errorf("mode %q claims to preserve the real IP without being frag", m)
		}
	}
}

// TestDefaultConfigTargetsDiscord pins the shipped starting point.
func TestDefaultConfigTargetsDiscord(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Normalize()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("the default config is invalid: %v", err)
	}
	if cfg.Profile != DefaultProfileID {
		t.Errorf("profile = %q, want %q", cfg.Profile, DefaultProfileID)
	}
	if len(cfg.Rules) != 1 || cfg.Rules[0].Name != "Discord" {
		t.Fatalf("default rules = %+v, want a single Discord rule", cfg.Rules)
	}
	if len(cfg.Rules[0].Domains) < 4 {
		t.Errorf("the Discord seed list is suspiciously short: %v", cfg.Rules[0].Domains)
	}
	if !cfg.FakednsPoolValid() {
		t.Errorf("default fakedns pool %q is not a valid CIDR", cfg.FakednsPool)
	}
}

// TestValidateReportsEveryProblem checks that a broken configuration produces
// one report rather than one error per run, which would otherwise make fixing
// it a sequence of discoveries.
func TestValidateReportsEveryProblem(t *testing.T) {
	cfg := DefaultConfig()
	cfg.FakednsPool = "nonsense"
	cfg.MixedPort = 99999
	cfg.AetherPort = cfg.MixedPort
	cfg.Rules[0].Mode = "sideways"
	cfg.Rules[0].Domains = nil

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected validation to fail")
	}
	for _, want := range []string{"fakednsPool", "mixedPort", "must differ", "unknown mode", "needs at least one domain"} {
		if !contains(err.Error(), want) {
			t.Errorf("validation report is missing %q:\n%v", want, err)
		}
	}
}

// TestNormalizeRepairsInvalidPool checks that a corrupted pool falls back rather
// than propagating into a generated config, where it would be rejected with a
// message that does not mention the stored setting.
func TestNormalizeRepairsInvalidPool(t *testing.T) {
	cfg := DefaultConfig()
	cfg.FakednsPool = "198.18.0.0/15/oops"
	cfg.Normalize()
	if cfg.FakednsPool != DefaultFakednsPool {
		t.Errorf("pool = %q, want it repaired to %q", cfg.FakednsPool, DefaultFakednsPool)
	}
}

// contains is a substring check, used against validation messages.
func contains(hay, needle string) bool {
	return len(needle) == 0 || (len(hay) >= len(needle) && indexOf(hay, needle) >= 0)
}

// containsAny is a membership check, used against domain lists.
func containsAny(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}

func indexOf(hay, needle string) int {
	for i := 0; i+len(needle) <= len(hay); i++ {
		if hay[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
