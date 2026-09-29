package config

import (
	"strings"
	"testing"

	"arclient/internal/model"
)

// gen is a small helper so each test reads as arrange-act-assert rather than
// three lines of setup.
func gen(t *testing.T, mutate func(*model.Config)) *XrayConfig {
	t.Helper()
	cfg := model.DefaultConfig()
	if mutate != nil {
		mutate(cfg)
	}
	cfg.Normalize()
	out, err := Generate(cfg, Options{LogLevel: "info", AccessLog: "access.log"})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	return out
}

// findRule returns the first routing rule with the given outbound tag.
func findRule(t *testing.T, x *XrayConfig, tag string) RoutingRule {
	t.Helper()
	for _, r := range x.Routing.Rules {
		if r.OutboundTag == tag {
			return r
		}
	}
	t.Fatalf("no routing rule with outboundTag %q; have %v", tag, tags(x))
	return RoutingRule{}
}

func tags(x *XrayConfig) []string {
	var out []string
	for _, r := range x.Routing.Rules {
		out = append(out, r.OutboundTag)
	}
	return out
}

func outbound(t *testing.T, x *XrayConfig, tag string) Outbound {
	t.Helper()
	for _, o := range x.Outbounds {
		if o.Tag == tag {
			return o
		}
	}
	t.Fatalf("no outbound %q", tag)
	return Outbound{}
}

// TestFragBArraysSurvive is the most important test in the file.
//
// The whole project rests on one field: fragB opens its ClientHello split with a
// zero-length fragment, which is the difference between the two source profiles
// on this network. If a refactor drops, reorders or "tidies" that value the
// build still passes and the core still starts, and the only symptom is that
// Discord stops working. So the arrays are asserted verbatim.
func TestFragBArraysSurvive(t *testing.T) {
	x := gen(t, nil)

	o := outbound(t, x, TagFragTLS)
	if o.Stream == nil || o.Stream.FinalMask == nil || len(o.Stream.FinalMask.TCP) == 0 {
		t.Fatal("frag-tls outbound has no TCP finalmask chain")
	}
	first, ok := o.Stream.FinalMask.TCP[0].Settings.(FragmentSettings)
	if !ok {
		t.Fatalf("first finalmask layer is %T, want FragmentSettings", o.Stream.FinalMask.TCP[0].Settings)
	}
	if first.Packets != "tlshello" {
		t.Errorf("packets = %q, want %q", first.Packets, "tlshello")
	}
	if want := []string{"0", "104", "1"}; !equalStrings(first.Lengths, want) {
		t.Errorf("lengths = %v, want %v (the leading zero is what defeats SNI filtering here)", first.Lengths, want)
	}
	if want := []string{"0"}; !equalStrings(first.Delays, want) {
		t.Errorf("delays = %v, want %v", first.Delays, want)
	}
	if first.MaxSplit != "0" {
		t.Errorf("maxSplit = %q, want %q", first.MaxSplit, "0")
	}
	if len(o.Stream.FinalMask.TCP) != 2 {
		t.Fatalf("frag-tls chain has %d layers, want 2", len(o.Stream.FinalMask.TCP))
	}
	second := o.Stream.FinalMask.TCP[1].Settings.(FragmentSettings)
	if want := []string{"114", "1"}; !equalStrings(second.Lengths, want) {
		t.Errorf("second layer lengths = %v, want %v", second.Lengths, want)
	}
	if second.MaxSplit != "11" {
		t.Errorf("second layer maxSplit = %q, want %q", second.MaxSplit, "11")
	}
}

// TestUDPCamouflagePulseCount pins the burst length. The count is part of the
// pattern, not an incidental detail of how the list was written.
func TestUDPCamouflagePulseCount(t *testing.T) {
	x := gen(t, func(c *model.Config) {
		c.Rules = []model.Rule{{
			Name: "udp", Mode: model.ModeFrag, Transport: model.TransportUDP,
			Enabled: true, Domains: []string{"example.org"},
		}}
	})
	o := outbound(t, x, TagFragUDP)
	if o.Stream == nil || o.Stream.FinalMask == nil || len(o.Stream.FinalMask.UDP) == 0 {
		t.Fatal("frag-udp outbound has no UDP finalmask")
	}
	n, ok := o.Stream.FinalMask.UDP[0].Settings.(NoiseSettings)
	if !ok {
		t.Fatalf("settings is %T, want NoiseSettings", o.Stream.FinalMask.UDP[0].Settings)
	}
	if len(n.Noise) != model.UDPNoisePulses {
		t.Errorf("noise pulses = %d, want %d", len(n.Noise), model.UDPNoisePulses)
	}
	if n.Reset != "28" {
		t.Errorf("noise reset = %q, want %q", n.Reset, "28")
	}
}

// TestKeepAliveSurvives guards a field that looks like cruft and is not.
//
// Discord's gateway is a long-lived WebSocket and the local NAT drops idle TCP.
// These two values are what keep it connected. Without them the client connects
// fine and then reports "Disconnected" minutes later, which looks like a flaky
// client or a filtering problem and is neither.
func TestKeepAliveSurvives(t *testing.T) {
	x := gen(t, nil)
	in := x.Inbounds[0]
	if in.Stream == nil || in.Stream.Sockopt == nil {
		t.Fatal("inbound has no sockopt")
	}
	so := in.Stream.Sockopt
	if so.TCPKeepAliveInterval == nil || *so.TCPKeepAliveInterval != 1 {
		t.Errorf("tcpKeepAliveInterval = %v, want 1", so.TCPKeepAliveInterval)
	}
	if so.TCPKeepAliveIdle == nil || *so.TCPKeepAliveIdle != 11 {
		t.Errorf("tcpKeepAliveIdle = %v, want 11", so.TCPKeepAliveIdle)
	}
}

// TestQUICBlockedForFragDomainsOnly covers the step that makes fragmentation do
// anything, and the deliberate narrowing of the source configs' global block.
//
// A QUIC connection contains no TLS ClientHello, so if a client negotiates QUIC
// the fragment chain never sees anything to split. The block is therefore
// required. The source configs apply it globally, which would also strip QUIC
// from traffic the user asked to leave alone, so it is scoped to frag domains.
func TestQUICBlockedForFragDomainsOnly(t *testing.T) {
	x := gen(t, nil)

	var quic, udp443 *RoutingRule
	for i := range x.Routing.Rules {
		switch {
		case len(x.Routing.Rules[i].Protocol) > 0 && x.Routing.Rules[i].Protocol[0] == "quic":
			quic = &x.Routing.Rules[i]
		case x.Routing.Rules[i].Port == "443" && x.Routing.Rules[i].OutboundTag == TagBlock:
			udp443 = &x.Routing.Rules[i]
		}
	}
	if quic == nil {
		t.Fatal("no QUIC block rule; fragmentation would silently never engage")
	}
	if udp443 == nil {
		t.Fatal("no UDP/443 block rule")
	}
	if len(quic.Domain) == 0 {
		t.Error("QUIC block is not scoped to frag domains, so it would affect unrelated traffic")
	}
	if !contains(quic.Domain, "discord.com") {
		t.Errorf("QUIC block does not cover discord.com: %v", quic.Domain)
	}
	if len(quic.IP) != 0 {
		t.Errorf("QUIC block carries an ip condition %v; it should be domain-scoped", quic.IP)
	}

	// The block has to precede the application frag rules, or the frag rule
	// claims the connection first and the block never runs. Compared by index
	// rather than by tag, because more than one rule now carries the frag-tls
	// tag: the resolver's own traffic is fragmented too, and that one is meant
	// to come first.
	blockIdx, appFragIdx := -1, -1
	for i, r := range x.Routing.Rules {
		if blockIdx < 0 && r.OutboundTag == TagBlock && len(r.Protocol) > 0 && r.Protocol[0] == "quic" {
			blockIdx = i
		}
		if appFragIdx < 0 && r.OutboundTag == TagFragTLS && len(r.InboundTag) == 0 {
			appFragIdx = i
		}
	}
	if blockIdx < 0 || appFragIdx < 0 {
		t.Fatalf("could not locate both rules; ladder is %v", tags(x))
	}
	if blockIdx > appFragIdx {
		t.Error("QUIC block is ordered after the application frag rule; it will never match")
	}
}

// TestUnlistedTrafficGoesDirectNotBlocked pins the deliberate deviation from the
// source configs, which end in a catch-all block. The requirement here is that
// unselected traffic is bypassed, not denied.
func TestUnlistedTrafficGoesDirectNotBlocked(t *testing.T) {
	x := gen(t, nil)

	last := x.Routing.Rules[len(x.Routing.Rules)-1]
	if last.OutboundTag != TagDirectTCP {
		t.Errorf("final rule outbound = %q, want %q: unselected traffic must be bypassed, not denied",
			last.OutboundTag, TagDirectTCP)
	}
	if last.Network != "tcp,udp" {
		t.Errorf("final rule network = %q, want %q", last.Network, "tcp,udp")
	}

	// The catch-all must be unconditioned.
	//
	// A proxy client hands the core a hostname, and with domainStrategy AsIs the
	// core does not resolve it, so an ip condition on the catch-all matches
	// nothing. Traffic then falls through to the first outbound, which is block.
	// The listed rules keep working, so the symptom is "only some things are
	// broken" — every unselected destination silently refused.
	if len(last.IP) != 0 || len(last.Domain) != 0 || last.Port != "" || len(last.Protocol) != 0 {
		t.Errorf("the final rule carries a condition %+v; an ip condition on the "+
			"catch-all never matches a hostname destination, and unlisted traffic "+
			"falls through to the block outbound", last)
	}

	for _, r := range x.Routing.Rules {
		if r.OutboundTag == TagBlock && len(r.Domain) == 0 && len(r.IP) == 0 {
			t.Errorf("found an unconditional block rule: %+v", r)
		}
	}
}

// TestResolverTrafficIsFragmented guards the rule that makes unlisted traffic
// resolve at all.
//
// The unfiltered resolver is DoH reached through domain fronting, and that
// request is subject to the same inspection as any other TLS handshake. Left
// unfragmented it is reset, no name resolves, and every destination outside the
// fake pool hangs.
//
// The failure is well camouflaged: selected domains are answered from the fake
// pool without touching the network, so the rules the user cares about keep
// working while everything else silently stalls. That is why this is asserted
// rather than left to be discovered again.
func TestResolverTrafficIsFragmented(t *testing.T) {
	x := gen(t, nil)

	var doh, domestic *RoutingRule
	for i := range x.Routing.Rules {
		r := &x.Routing.Rules[i]
		if len(r.InboundTag) == 0 {
			continue
		}
		switch r.InboundTag[0] {
		case "no-filter-dns":
			doh = r
		case "domestic-dns":
			if domestic == nil {
				domestic = r
			}
		}
	}
	if doh == nil {
		t.Fatal("no rule claims the unfiltered resolver's traffic; its DoH request " +
			"would be reset and nothing outside the fake pool would resolve")
	}
	if doh.OutboundTag != TagFragTLS {
		t.Errorf("the DoH resolver routes to %q, want %q: an unfragmented fronted "+
			"request is filtered", doh.OutboundTag, TagFragTLS)
	}
	if domestic == nil {
		t.Fatal("no rule claims the system resolver's traffic")
	}
	if domestic.OutboundTag != TagDirectTCP {
		t.Errorf("the system resolver routes to %q, want %q", domestic.OutboundTag, TagDirectTCP)
	}

	// The resolver rules must precede the application domain rules, or a query
	// for a selected domain would be claimed by that domain's frag rule instead.
	dohIdx, fragIdx := -1, -1
	for i, r := range x.Routing.Rules {
		if doh != nil && len(r.InboundTag) > 0 && r.InboundTag[0] == "no-filter-dns" && dohIdx < 0 {
			dohIdx = i
		}
		if r.OutboundTag == TagFragTLS && len(r.InboundTag) == 0 && fragIdx < 0 {
			fragIdx = i
		}
	}
	if dohIdx > fragIdx {
		t.Error("the resolver rule is ordered after the application frag rule and will never match")
	}
}

// TestNoResolverRuleWithoutFragOutbound checks the generator never references an
// outbound it did not emit. A rule naming a missing tag makes the core refuse to
// start, with an error that does not point at the tag.
func TestNoResolverRuleWithoutFragOutbound(t *testing.T) {
	x := gen(t, func(c *model.Config) {
		c.Rules = []model.Rule{{
			Name: "tunnel only", Mode: model.ModeTunnel, Transport: model.TransportTCP,
			Enabled: true, Domains: []string{"web.telegram.org"},
		}}
	})
	present := map[string]bool{}
	for _, o := range x.Outbounds {
		present[o.Tag] = true
	}
	for _, r := range x.Routing.Rules {
		if !present[r.OutboundTag] {
			t.Errorf("routing rule references outbound %q, which is not declared; "+
				"declared: %v", r.OutboundTag, present)
		}
	}
}

// TestEveryRuleReferencesADeclaredOutbound generalises the above to all shapes.
func TestEveryRuleReferencesADeclaredOutbound(t *testing.T) {
	for _, rules := range [][]model.Rule{
		{{Name: "a", Mode: model.ModeFrag, Transport: model.TransportTCP, Enabled: true, Domains: []string{"a.com"}}},
		{{Name: "a", Mode: model.ModeFrag, Transport: model.TransportUDP, Enabled: true, Domains: []string{"a.com"}}},
		{{Name: "a", Mode: model.ModeTunnel, Transport: model.TransportBoth, Enabled: true, Domains: []string{"a.com"}}},
		{
			{Name: "a", Mode: model.ModeFrag, Transport: model.TransportBoth, Enabled: true, Domains: []string{"a.com"}},
			{Name: "b", Mode: model.ModeTunnel, Transport: model.TransportBoth, Enabled: true, Domains: []string{"b.com"}},
		},
	} {
		x := gen(t, func(c *model.Config) { c.Rules = rules })
		present := map[string]bool{}
		for _, o := range x.Outbounds {
			present[o.Tag] = true
		}
		for _, r := range x.Routing.Rules {
			if !present[r.OutboundTag] {
				t.Errorf("rule %+v references undeclared outbound %q", r, r.OutboundTag)
			}
		}
	}
}

// TestFakednsIncludesResolverBootstrap guards the single most easily lost value
// in the whole configuration.
//
// The unfiltered resolver is DoH to cloudflare-dns.com, fronted onto
// challenges.cloudflare.com. Resolving the fronting target needs a resolver, and
// the resolver is the DoH client, which needs to resolve cloudflare-dns.com. The
// loop is broken only by a fake answer for the fronting target, so that entry
// has to be in the fakedns list unconditionally.
//
// It is also the hardest failure to diagnose. Selected domains are answered from
// the fake pool without touching the network, so every configured rule keeps
// working and only unselected destinations hang. That was found by running the
// generator and verbatim FragB side by side on the same machine: FragB
// answered for unlisted names, and the generated configuration did not, with no
// error from either.
func TestFakednsIncludesResolverBootstrap(t *testing.T) {
	x := gen(t, nil)
	_, domains := fakeAddress(t, x, x.DNS.Servers[0])
	if !contains(domains, ResolverBootstrapDomain) {
		t.Fatalf("the fakedns list has no bootstrap entry; got %v\n"+
			"without it the DoH resolver cannot resolve its own fronting target, "+
			"and every destination outside the fake pool hangs", domains)
	}
	if domains[0] != ResolverBootstrapDomain {
		t.Errorf("the bootstrap entry is at position %d, want first", indexOf(domains, ResolverBootstrapDomain))
	}
	// And it must survive even with no user rules at all, since the resolver
	// does not care whether the user has configured anything.
	empty := gen(t, func(c *model.Config) { c.Rules = nil })
	_, emptyDomains := fakeAddress(t, empty, empty.DNS.Servers[0])
	if !contains(emptyDomains, ResolverBootstrapDomain) {
		t.Error("the bootstrap entry is conditional on having user rules")
	}
}

// TestFrontedResolverHostMatchesBootstrap keeps the two halves of the fronting
// arrangement tied together. They are separate constants because one is a DNS
// host override and the other is a match-type rule, and nothing but this test
// would notice if they drifted apart.
func TestFrontedResolverHostMatchesBootstrap(t *testing.T) {
	if ResolverBootstrapDomain != "full:"+ResolverFrontingHost {
		t.Fatalf("the bootstrap domain %q does not name the fronting host %q",
			ResolverBootstrapDomain, ResolverFrontingHost)
	}
	x := gen(t, nil)
	fronted, ok := x.DNS.Hosts["cloudflare-dns.com"]
	if !ok {
		t.Fatal("cloudflare-dns.com is not fronted")
	}
	if fronted != ResolverFrontingHost {
		t.Errorf("the DoH resolver is fronted onto %q, but the bootstrap entry names %q",
			fronted, ResolverFrontingHost)
	}
}

// TestFakednsCoversSelectedOnly is what makes selective capture work.
//
// fakedns must answer selected domains and nothing else. Widening it puts
// unselected traffic into the tunnel, which is the opposite of the requirement
// and turns a proxy problem into a total outage.
func TestFakednsCoversSelectedOnly(t *testing.T) {
	x := gen(t, func(c *model.Config) {
		c.Rules = []model.Rule{
			{Name: "frag", Mode: model.ModeFrag, Transport: model.TransportBoth, Enabled: true, Domains: []string{"discord.com"}},
			{Name: "tunnel", Mode: model.ModeTunnel, Transport: model.TransportBoth, Enabled: true, Domains: []string{"web.telegram.org"}},
			{Name: "bypass", Mode: model.ModeDirect, Transport: model.TransportBoth, Enabled: true, Domains: []string{"example.ir"}},
		}
	})

	fake := x.DNS.Servers[0]
	pool, domains := fakeAddress(t, x, fake)
	if pool != model.DefaultFakednsPool {
		t.Errorf("fakedns pool = %q, want %q", pool, model.DefaultFakednsPool)
	}
	if !contains(domains, "discord.com") {
		t.Errorf("fakedns does not cover the frag domain: %v", domains)
	}
	if !contains(domains, "web.telegram.org") {
		t.Errorf("fakedns does not cover the tunnel domain: %v", domains)
	}
	if contains(domains, "example.ir") {
		t.Errorf("fakedns covers a direct rule, which would pull bypassed traffic into the tunnel: %v", domains)
	}
}

// TestFakednsPoolIsSharedWithZeptun covers the failure mode that cannot be
// caught any other way.
//
// The fake pool is the tunnel's include list. If the two generators ever read
// different values, selected traffic resolves into the fake range and is then
// routed straight out of the physical NIC, because the tunnel is not watching
// it. Nothing errors. The UI would still say the traffic is tunnelled. So this
// asserts the two documents agree.
func TestFakednsPoolIsSharedWithZeptun(t *testing.T) {
	cfg := model.DefaultConfig()
	cfg.FakednsPool = "198.19.0.0/16" // deliberately not the default
	cfg.Normalize()

	x, err := Generate(cfg, Options{})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	toml, err := ZeptunTOML(cfg, ZeptunOptions{})
	if err != nil {
		t.Fatalf("ZeptunTOML: %v", err)
	}

	_, domains := fakeAddress(t, x, x.DNS.Servers[0])
	if len(domains) == 0 {
		t.Fatal("fakedns has no domains")
	}
	pool, _ := fakeAddress(t, x, x.DNS.Servers[0])
	if !strings.Contains(toml, `include = ["`+pool+`"]`) {
		t.Errorf("zeptun include list does not carry the core's fake pool %q:\n%s", pool, toml)
	}
}

// TestAutoResolvesDirectUntilEscalated covers the voice decision path.
//
// An auto rule starts direct because a working direct path costs nothing and
// keeps the flow out of the tunnel. Only a failed direct probe escalates it.
// Getting this backwards fragments voice traffic for no reason, or tunnels it
// when it did not need it, and either way the user cannot tell why.
func TestAutoResolvesDirectUntilEscalated(t *testing.T) {
	auto := model.Rule{
		Name: "voice", Mode: model.ModeAuto, Transport: model.TransportUDP,
		Enabled: true, Domains: []string{"voice.discord.gg"},
	}

	x := gen(t, func(c *model.Config) { c.Rules = []model.Rule{auto} })
	if got := findRuleTagDomains(t, x, TagTunnel); len(got) > 0 {
		t.Errorf("un-escalated auto rule produced tunnel rules: %v", got)
	}
	if includes := fakednsDomains(t, x); contains(includes, "voice.discord.gg") {
		t.Errorf("un-escalated auto rule is in the tunnel include list: %v", includes)
	}

	escalated := auto
	escalated.AutoEscalated = true
	x = gen(t, func(c *model.Config) { c.Rules = []model.Rule{escalated} })
	if got := findRuleTagDomains(t, x, TagTunnel); !contains(got, "voice.discord.gg") {
		t.Errorf("escalated auto rule did not produce a tunnel rule; have %v", got)
	}
	if includes := fakednsDomains(t, x); !contains(includes, "voice.discord.gg") {
		t.Errorf("escalated auto rule missing from the tunnel include list: %v", includes)
	}
}

// TestDisabledRulesProduceNothing keeps a switched-off rule from quietly
// claiming traffic.
func TestDisabledRulesProduceNothing(t *testing.T) {
	x := gen(t, func(c *model.Config) {
		c.Rules[0].Enabled = false
	})
	for _, r := range x.Routing.Rules {
		for _, d := range r.Domain {
			if d == "discord.com" {
				t.Errorf("a disabled rule still appears in rule %+v", r)
			}
		}
	}
	// The list is not empty: the resolver bootstrap entry is unconditional and
	// is not a user rule. What must be absent is the disabled rule's domain.
	_, domains := fakeAddress(t, x, x.DNS.Servers[0])
	if contains(domains, "discord.com") {
		t.Errorf("a disabled rule still appears in the fakedns domain list: %v", domains)
	}
	if !contains(domains, ResolverBootstrapDomain) {
		t.Errorf("disabling every rule also removed the resolver bootstrap entry: %v", domains)
	}
}

// TestGeoRulesOnlyWhenStaged checks that a build without geo data does not emit
// a geoip reference, because the core refuses to start when a referenced asset
// is missing, and the symptom looks nothing like a missing file.
func TestGeoRulesOnlyWhenStaged(t *testing.T) {
	// Several rules share the direct tag now, so the one being asserted is the
	// one carrying an address condition.
	findAddressRule := func(t *testing.T, x *XrayConfig) RoutingRule {
		t.Helper()
		for _, r := range x.Routing.Rules {
			if r.OutboundTag == TagDirectTCP && len(r.IP) > 0 {
				return r
			}
		}
		t.Fatalf("no direct rule with an address condition; ladder is %v", tags(x))
		return RoutingRule{}
	}

	x := gen(t, func(c *model.Config) { c.WithGeo = false })
	for _, r := range x.Routing.Rules {
		for _, ip := range r.IP {
			if strings.HasPrefix(ip, "geoip:") || strings.HasPrefix(ip, "geosite:") {
				t.Errorf("rule %+v references geo data but WithGeo is false", r)
			}
		}
	}
	x = gen(t, func(c *model.Config) { c.WithGeo = true })
	if !contains(findAddressRule(t, x).IP, "geoip:ir") {
		t.Error("WithGeo is true but geoip:ir is missing from the direct rule")
	}
}

// TestVersionGateIsEmitted checks the core is told the floor it must meet. The
// fragment lengths/delays arrays only exist from this version on, so a config
// the running core cannot honour is worse than one that is refused.
func TestVersionGateIsEmitted(t *testing.T) {
	x := gen(t, nil)
	if x.Version.Min != model.XrayVersionMin {
		t.Errorf("version.min = %q, want %q", x.Version.Min, model.XrayVersionMin)
	}
}

// TestLoopbackOnlyListeners checks the listeners are not exposed off-machine.
// Aether's SOCKS5 has no authentication at all, so loopback binding is the only
// thing keeping other local processes out of the tunnel.
func TestLoopbackOnlyListeners(t *testing.T) {
	// Needs a tunnel rule, because the tunnel outbound is only emitted when
	// something routes to it.
	x := gen(t, func(c *model.Config) {
		c.Rules = append(c.Rules, model.Rule{
			Name: "telegram", Mode: model.ModeTunnel, Transport: model.TransportBoth,
			Enabled: true, Domains: []string{"web.telegram.org"},
		})
	})
	if x.Inbounds[0].Listen != ListenAddr {
		t.Errorf("inbound listens on %q, want %q", x.Inbounds[0].Listen, ListenAddr)
	}
	tun := outbound(t, x, TagTunnel)
	if len(tun.Settings.Servers) != 1 || tun.Settings.Servers[0].Address != ListenAddr {
		t.Errorf("tunnel outbound points at %+v, want loopback", tun.Settings.Servers)
	}
	if tun.Settings.Servers[0].Port == 0 {
		t.Error("tunnel outbound has no port")
	}
}

// TestGenerateRejectsInvalidConfig checks the generator refuses rather than
// emitting something the core will reject at startup, where the error message
// does not point at the actual mistake.
func TestGenerateRejectsInvalidConfig(t *testing.T) {
	for name, mutate := range map[string]func(*model.Config){
		"bad pool":     func(c *model.Config) { c.FakednsPool = "not-a-cidr" },
		"unknown mode": func(c *model.Config) { c.Rules[0].Mode = "sideways" },
		"same ports":   func(c *model.Config) { c.AetherPort = c.MixedPort },
		"no domains":   func(c *model.Config) { c.Rules[0].Domains = nil },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := model.DefaultConfig()
			mutate(cfg)
			if _, err := Generate(cfg, Options{}); err == nil {
				t.Fatal("expected Generate to reject this config")
			}
		})
	}
}

// TestFragAKeptAsVariant makes sure the non-working profile is still reachable
// for when fragB stops working, and is clearly not the default.
func TestFragAKeptAsVariant(t *testing.T) {
	cfg := model.DefaultConfig()
	if cfg.Profile != "fragB" {
		t.Errorf("default profile = %q, want fragB", cfg.Profile)
	}
	a, ok := cfg.Profiles["fragA"]
	if !ok {
		t.Fatal("fragA is missing; it is the fallback when fragB stops working")
	}
	if a.Recommended {
		t.Error("fragA is marked recommended")
	}
	step := a.TCPTLS[0]
	if step.Lengths[0] != "6" {
		t.Errorf("fragA first length = %q, want %q", step.Lengths[0], "6")
	}
}

// --- helpers ---

// fakeAddress pulls the pool and domain list out of the fakedns resolver.
//
// The pool lives in the top-level fakedns key, not on the resolver entry, so it
// is read from the config rather than the server.
func fakeAddress(t *testing.T, x *XrayConfig, s DNSServer) (pool string, domains []string) {
	t.Helper()
	if s.Address != "fakedns" {
		t.Fatalf("expected the fakedns resolver, got %q", s.Address)
	}
	if x.FakeDNS == nil {
		t.Fatal("config has no fakedns block; selected domains would resolve normally and never enter the tunnel")
	}
	return x.FakeDNS.IPPool, s.Domains
}

// before reports whether tag a appears earlier in the ladder than tag b.
func before(x *XrayConfig, a, b string) bool {
	ai, bi := -1, -1
	for i, r := range x.Routing.Rules {
		if r.OutboundTag == a && ai < 0 {
			ai = i
		}
		if r.OutboundTag == b && bi < 0 {
			bi = i
		}
	}
	return ai >= 0 && bi >= 0 && ai < bi
}

func findRuleTagDomains(t *testing.T, x *XrayConfig, tag string) []string {
	t.Helper()
	var out []string
	for _, r := range x.Routing.Rules {
		if r.OutboundTag == tag {
			out = append(out, r.Domain...)
		}
	}
	return out
}

// fakednsDomains reads the domain list the core answers the fake pool for.
func fakednsDomains(t *testing.T, x *XrayConfig) []string {
	t.Helper()
	_, d := fakeAddress(t, x, x.DNS.Servers[0])
	return d
}

func contains(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}

func indexOf(hay []string, needle string) int {
	for i, h := range hay {
		if h == needle {
			return i
		}
	}
	return -1
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
