package discovery

import "testing"

// TestParseLine covers the access log shape the core emits.
func TestParseLine(t *testing.T) {
	line := `2026/09/29 12:00:01 from 127.0.0.1:52344 accepted tcp:discord.com:443 [mixed-in >> frag-tls] email: n`
	e, ok := ParseLine(line)
	if !ok {
		t.Fatal("failed to parse a well-formed access line")
	}
	if e.Network != "tcp" {
		t.Errorf("network = %q, want tcp", e.Network)
	}
	if e.Host != "discord.com" {
		t.Errorf("host = %q, want discord.com", e.Host)
	}
	if e.Port != 443 {
		t.Errorf("port = %d, want 443", e.Port)
	}
	if e.Inbound != "mixed-in" {
		t.Errorf("inbound = %q, want mixed-in", e.Inbound)
	}
	if e.Outbound != FragTLS {
		t.Errorf("outbound = %q, want %q", e.Outbound, FragTLS)
	}
}

// TestParseLineRejectsNoise checks that unrecognised lines are skipped rather
// than guessed at. A parser that invents a host from a line it did not
// understand would put fabricated domains into a routing rule.
func TestParseLineRejectsNoise(t *testing.T) {
	for _, line := range []string{
		"",
		"this is not an access log line",
		`2026/09/29 accepted tcp:discord.com:notanumber [in >> out]`,
		`accepted tcp:discord.com:443 [mixed-in >> frag-tls`, // truncated tag pair
	} {
		if _, ok := ParseLine(line); ok {
			t.Errorf("parsed %q, which should have been rejected", line)
		}
	}
}

// TestParseLineToleratesMissingTimestamp documents a deliberate leniency: the
// parser keys on the routing part of the line, so it keeps working if the
// core's log prefix changes. Being strict about the prefix would turn a
// cosmetic upstream change into a discovery report with nothing in it.
func TestParseLineToleratesMissingTimestamp(t *testing.T) {
	e, ok := ParseLine(`accepted udp:1.2.3.4:53 [a >> b]`)
	if !ok {
		t.Fatal("failed to parse a routing segment with no timestamp")
	}
	if e.Host != "1.2.3.4" || e.Port != 53 || e.Network != "udp" {
		t.Errorf("parsed %+v, want the literal address preserved", e)
	}
}

// TestDirectHostsFindsTheForgottenDomain is the behaviour this package exists
// for: a domain that reached a direct outbound when a rule should have claimed
// it. That is how a missing CDN suffix gets found, and a missing CDN suffix is
// how Discord ends up half-working.
func TestDirectHostsFindsTheForgottenDomain(t *testing.T) {
	rep := Analyse([]string{
		`accepted tcp:discord.com:443 [mixed-in >> frag-tls]`,
		`accepted tcp:cdn.discordapp.com:443 [mixed-in >> frag-tls]`,
		// The one that was left out of the rule.
		`accepted tcp:images-ext-2.discordapp.net:443 [mixed-in >> tcp-direct]`,
		// Genuinely unlisted, and meant to be.
		`accepted tcp:example.ir:80 [mixed-in >> tcp-direct]`,
	})

	direct := rep.DirectHosts()
	if len(direct) != 2 {
		t.Fatalf("direct hosts = %v, want 2", direct)
	}
	if !has(direct, "images-ext-2.discordapp.net") {
		t.Errorf("the uncovered CDN domain is missing from %v", direct)
	}

	covered := rep.Covered()
	if len(covered) != 2 {
		t.Errorf("covered = %v, want the two frag domains", covered)
	}
}

// TestDirectHostsIgnoresMixedUsage checks that a domain which also used a
// covered outbound is not reported.
//
// A domain can be reached both ways legitimately: an IP range shared between
// covered and uncovered services, or a rule that escalated mid-session. Calling
// that a finding trains the user to ignore the report.
func TestDirectHostsIgnoresMixedUsage(t *testing.T) {
	rep := Analyse([]string{
		`accepted tcp:discord.com:443 [mixed-in >> frag-tls]`,
		`accepted tcp:discord.com:443 [mixed-in >> tcp-direct]`,
	})
	if got := rep.DirectHosts(); len(got) != 0 {
		t.Errorf("direct hosts = %v, want none: the domain was covered by a rule", got)
	}
}

// TestBlockedIsSeparate covers the other failure shape: a rule matched and then
// denied the connection. That is a transport problem, not a missing domain, and
// conflating the two sends the user looking in the wrong place.
func TestBlockedIsSeparate(t *testing.T) {
	rep := Analyse([]string{
		`accepted udp:discord.com:443 [mixed-in >> block]`,
	})
	if got := rep.Blocked(); len(got) != 1 || got[0] != "discord.com" {
		t.Errorf("blocked = %v, want [discord.com]", got)
	}
	if got := rep.DirectHosts(); len(got) != 0 {
		t.Errorf("a blocked domain was also reported as direct: %v", got)
	}
	if got := rep.Covered(); len(got) != 0 {
		t.Errorf("a blocked domain was also reported as covered: %v", got)
	}
}

// TestUnparsedIsCounted guards the report's own reliability: a large unparsed
// count means the log format moved and the analysis should not be trusted.
func TestUnparsedIsCounted(t *testing.T) {
	rep := Analyse([]string{
		`accepted tcp:discord.com:443 [mixed-in >> frag-tls]`,
		"something new",
		"something else",
	})
	if rep.Unparsed != 2 {
		t.Errorf("unparsed = %d, want 2", rep.Unparsed)
	}
	if len(rep.Entries) != 1 {
		t.Errorf("entries = %d, want 1", len(rep.Entries))
	}
}

// TestSuffixesSuggestsTheShortestCover keeps a discovery report from proposing
// forty domain entries where one would do.
func TestSuffixesSuggestsTheShortestCover(t *testing.T) {
	got := Suffixes([]string{
		"cdn.discordapp.com",
		"images-ext-1.discordapp.net",
		"images-ext-2.discordapp.net",
		"media.discordapp.net",
	})
	want := []string{"discordapp.com", "discordapp.net"}
	if len(got) != len(want) {
		t.Fatalf("suffixes = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("suffixes = %v, want %v", got, want)
			break
		}
	}
}

// TestSuffixesDoesNotOverreach keeps unrelated services in separate rules. Two
// hosts sharing a bare TLD are not evidence that one rule covers both.
func TestSuffixesDoesNotOverreach(t *testing.T) {
	got := Suffixes([]string{"a.example.com", "b.example.org"})
	want := []string{"example.com", "example.org"}
	if len(got) != len(want) {
		t.Fatalf("suffixes = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("suffixes = %v, want %v", got, want)
		}
	}
}

// TestSuffixesKeepsSecondLevelCountryDomains checks the small public-suffix
// heuristic. Truncating "example.co.uk" to "co.uk" would suggest a rule that
// covers an entire country's second-level namespace.
func TestSuffixesKeepsSecondLevelCountryDomains(t *testing.T) {
	got := Suffixes([]string{"a.example.co.uk", "b.example.co.uk"})
	if len(got) != 1 || got[0] != "example.co.uk" {
		t.Errorf("suffixes = %v, want [example.co.uk]", got)
	}
}

func has(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}
