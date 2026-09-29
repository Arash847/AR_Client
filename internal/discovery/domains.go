// Package discovery finds the domains an application actually contacts.
//
// This exists because a partial domain list does not fail loudly. A Discord
// rule missing its CDN suffix produces a client where messages work, avatars
// do not, video will not play and uploads hang. That reads as a flaky
// application, and the cause is invisible from the symptom.
//
// The signal that finds it is the one the generated config produces for free:
// every routed connection is logged with the outbound tag it was matched to. A
// domain that reached "direct" while the user believes it is covered by a frag
// or tunnel rule is a domain that was left out, and it is reported by name.
//
// The distinction this package is careful about is between a domain that
// reached direct *because it was meant to* and one that reached direct *by
// omission*. Only the second is a finding, and collapsing the two would produce
// a report full of noise that trains the user to ignore it.
package discovery

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Entry is one parsed access-log line.
type Entry struct {
	// Network is "tcp" or "udp".
	Network string
	// Host is the destination as the core saw it. A fake address is mapped
	// back to its domain before logging, so this is a name whenever the
	// resolver knew one.
	Host string
	Port int
	// Inbound and Outbound are the routing tags.
	Inbound  string
	Outbound string
	// Raw is the original line, kept so a report can quote evidence rather
	// than assert.
	Raw string
}

// DirectTag and friends are the outbound tags the generator emits. They are
// duplicated here rather than imported so this package stays usable against an
// access log from a configuration file the user edited by hand.
const (
	DirectTag = "tcp-direct"
	FragTLS   = "frag-tls"
	FragPlain = "frag-plain"
	FragUDP   = "frag-udp"
	TunnelTag = "tunnel"
	BlockTag  = "block"
)

// accessLine matches the core's access log shape:
//
//	<timestamp> from <addr> accepted tcp:host:port [inbound >> outbound] ...
//
// The host group is non-greedy on the port boundary so a name and a literal
// address are both captured, and the bracketed tag pair is captured whole
// because the separator inside it is fixed but the names are generated.
var accessLine = regexp.MustCompile(
	`accepted\s+(tcp|udp):([^:\s]+):(\d+)\s+\[([^\]\s]+)\s*>>\s*([^\]\s]+)\]`)

// ParseLine parses one access-log line. It reports false for anything it does
// not recognise, so an unrecognised line is skipped rather than guessed at.
func ParseLine(line string) (Entry, bool) {
	m := accessLine.FindStringSubmatch(line)
	if m == nil {
		return Entry{}, false
	}
	port, err := strconv.Atoi(m[3])
	if err != nil {
		return Entry{}, false
	}
	return Entry{
		Network:  m[1],
		Host:     strings.ToLower(m[2]),
		Port:     port,
		Inbound:  m[4],
		Outbound: m[5],
		Raw:      strings.TrimSpace(line),
	}, true
}

// Finding is a domain that reached a direct outbound despite being covered.
type Finding struct {
	Host string
	// Wanted is the rule the domain was expected to match, if one covered it.
	Wanted string
	// Count is how many connections were seen.
	Count int
	// Sample is one raw log line, so the finding can be checked against what
	// actually happened rather than taken on trust.
	Sample string
}

// Report is the result of analysing a set of log lines.
type Report struct {
	// Domains maps each destination domain to the set of outbounds it used.
	Domains map[string]map[string]int
	// Entries is every parsed line, in order.
	Entries []Entry
	// Unparsed counts lines that did not match. A high number means the core's
	// log format changed and the report should not be trusted.
	Unparsed int
}

// Analyse parses log lines and indexes them by destination.
func Analyse(lines []string) Report {
	r := Report{Domains: map[string]map[string]int{}}
	for _, line := range lines {
		e, ok := ParseLine(line)
		if !ok {
			r.Unparsed++
			continue
		}
		r.Entries = append(r.Entries, e)
		byOut, ok := r.Domains[e.Host]
		if !ok {
			byOut = map[string]int{}
			r.Domains[e.Host] = byOut
		}
		byOut[e.Outbound]++
	}
	return r
}

// DirectHosts returns the domains that used only direct outbounds.
//
// These are the candidates worth looking at: under a correct configuration
// every domain the user asked to cover should appear with a frag or tunnel tag
// somewhere in the log, and a domain that only ever appears as direct was never
// claimed by anything.
func (r Report) DirectHosts() []string {
	var out []string
	for host, byOut := range r.Domains {
		onlyDirect := true
		for tag := range byOut {
			if tag != DirectTag {
				onlyDirect = false
				break
			}
		}
		if onlyDirect {
			out = append(out, host)
		}
	}
	sort.Strings(out)
	return out
}

// Covered returns the domains that used a frag or tunnel outbound, which is
// what a correctly matched configuration should produce.
func (r Report) Covered() []string {
	var out []string
	for host, byOut := range r.Domains {
		for tag := range byOut {
			if tag == FragTLS || tag == FragPlain || tag == FragUDP || tag == TunnelTag {
				out = append(out, host)
				break
			}
		}
	}
	sort.Strings(out)
	return out
}

// Blocked returns domains that were blocked outright. A blocked domain under a
// rule the user believes is covered is a different failure from an uncovered
// one, and worth naming separately: it means the rule matched and then denied
// the connection, which is usually a transport-level problem rather than a
// missing domain.
func (r Report) Blocked() []string {
	var out []string
	for host, byOut := range r.Domains {
		if byOut[BlockTag] > 0 {
			out = append(out, host)
		}
	}
	sort.Strings(out)
	return out
}

// secondLevel are the labels that commonly appear between a registrable name
// and a country code, so that "example.co.uk" is not truncated to "co.uk".
//
// This is a short heuristic list rather than a public suffix list on purpose.
// The consequence of a wrong guess is a suggestion that covers slightly too
// much, which the caller is expected to check before applying; carrying a full
// suffix list would be a large dependency for a cosmetic improvement.
var secondLevel = map[string]bool{
	"co": true, "com": true, "net": true, "org": true,
	"gov": true, "ac": true, "edu": true, "or": true,
}

// Suffixes reduces observed hosts to the shortest suffix that identifies a
// service, so a report can suggest one rule instead of forty.
//
// Every host collapses to its last two labels, or three when the pair would
// straddle a country code, so "cdn.discordapp.com" and "images-ext-1.discordapp.net"
// become "discordapp.com" and "discordapp.net". That is a suggestion, not an
// application: the caller must check a candidate against the rules already
// configured before adding it, because a suffix that matches something the user
// routed deliberately is how a discovery tool moves traffic nobody asked it to
// move.
func Suffixes(hosts []string) []string {
	seen := make(map[string]bool, len(hosts))
	var out []string
	for _, h := range hosts {
		labels := strings.Split(strings.ToLower(h), ".")
		if len(labels) < 2 {
			continue
		}
		n := 2
		if len(labels) >= 3 && len(labels[len(labels)-1]) == 2 && secondLevel[labels[len(labels)-2]] {
			n = 3
		}
		if len(labels) < n {
			n = len(labels)
		}
		cand := strings.Join(labels[len(labels)-n:], ".")
		if cand == "" || seen[cand] {
			continue
		}
		seen[cand] = true
		out = append(out, cand)
	}
	sort.Strings(out)
	return out
}
