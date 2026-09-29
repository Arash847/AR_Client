package config

// Go mirrors of the subset of the xray JSON schema that ARClient generates.
//
// Only the fields ARClient actually sets are modelled. Encoding them as real
// structs rather than map[string]any means a typo becomes a compile error
// instead of a core that starts and silently ignores the setting — which for
// the sockopt fields in particular would look like a filtering fault rather
// than a config bug.

import "encoding/json"

// XrayConfig is a complete core configuration.
type XrayConfig struct {
	Remarks string  `json:"remarks,omitempty"`
	Version Version `json:"version"`
	Log     Log     `json:"log"`
	Policy  Policy  `json:"policy"`
	// FakeDNS declares the address pool the fakedns resolver answers from.
	//
	// It is a top-level key rather than a field on the resolver entry, which is
	// not obvious and was found here by having the core reject the config. The
	// pool is the most consequential value in this document: it is the range
	// the tunnel watches, so a mismatch between it and the tunnel's include
	// list sends selected traffic straight out of the physical NIC while every
	// indicator claims it is tunnelled.
	FakeDNS   *FakeDNS   `json:"fakedns,omitempty"`
	DNS       DNS        `json:"dns"`
	Inbounds  []Inbound  `json:"inbounds"`
	Outbounds []Outbound `json:"outbounds"`
	Routing   Routing    `json:"routing"`
}

// FakeDNS is the fake address pool.
type FakeDNS struct {
	IPPool string `json:"ipPool"`
	// PoolSize bounds the mapping cache. Left at the core's default when zero.
	PoolSize int `json:"poolSize,omitempty"`
}

// Version is the core's version gate. The fragment finalmask's lengths/delays
// arrays only exist from XrayVersionMin onwards, so emitting a config the
// running core cannot honour is worse than refusing to start.
type Version struct {
	Min string `json:"min"`
}

// Log configures core logging. Access logging is off by default and switched on
// only for domain discovery, because it is the difference between finding a
// forgotten domain and not finding it.
type Log struct {
	LogLevel string `json:"loglevel"`
	DNSLog   bool   `json:"dnsLog"`
	Access   string `json:"access"`
	Error    string `json:"error"`
}

// Policy holds the connection lifetime limits.
type Policy struct {
	Levels map[string]PolicyLevel `json:"levels"`
}

// PolicyLevel is one user level's limits.
type PolicyLevel struct {
	UplinkOnly   int `json:"uplinkOnly"`
	DownlinkOnly int `json:"downlinkOnly"`
	ConnIdle     int `json:"connIdle,omitempty"`
}

// DNS is the core's resolver configuration.
type DNS struct {
	Hosts          map[string]string `json:"hosts"`
	Servers        []DNSServer       `json:"servers"`
	QueryStrategy  string            `json:"queryStrategy,omitempty"`
	UseSystemHosts bool              `json:"useSystemHosts"`
	ServeStale     bool              `json:"serveStale"`
	DisableCache   bool              `json:"disableCache,omitempty"`
}

// DNSServer is one resolver entry.
//
// Address is a plain string for every kind used here: "fakedns",
// "localhost", or a DoH URL. The core's NameServerConfig also accepts an object
// form, but nothing in this configuration needs it, and modelling only the
// string form keeps a malformed address a compile-time impossibility rather
// than a runtime surprise.
type DNSServer struct {
	Address string   `json:"address"`
	Port    int      `json:"port,omitempty"`
	Domains []string `json:"domains,omitempty"`
	Tag     string   `json:"tag,omitempty"`
	// TimeoutMs and FinalQuery are only meaningful on the tagged servers. The
	// fakedns entry deliberately omits both.
	TimeoutMs  int  `json:"timeoutMs,omitempty"`
	FinalQuery bool `json:"finalQuery,omitempty"`
}

// Inbound is a listening socket.
type Inbound struct {
	Tag      string          `json:"tag"`
	Listen   string          `json:"listen"`
	Port     int             `json:"port"`
	Protocol string          `json:"protocol"`
	Sniffing *Sniffing       `json:"sniffing,omitempty"`
	Settings InboundSettings `json:"settings"`
	Stream   *StreamSettings `json:"streamSettings,omitempty"`
}

// InboundSettings configures the mixed inbound.
type InboundSettings struct {
	UDP bool `json:"udp"`
	// Auth, when set, turns the listener into an authenticated proxy. Left nil
	// so the loopback listener stays open only to this machine.
	Auth *InboundAuth `json:"auth,omitempty"`
}

// InboundAuth is HTTP proxy authentication.
type InboundAuth struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Sniffing recovers the real destination from the first packets of a
// connection.
type Sniffing struct {
	Enabled bool `json:"enabled"`
	// DestOverride must include "fakedns" or a fake-IP connection cannot be
	// mapped back to a domain, and it must include "tls" because that is where
	// the SNI that the routing rules match on actually comes from.
	DestOverride []string `json:"destOverride"`
	// RouteOnly false lets a sniffed domain replace the dial target, which is
	// what lets a connection that arrived as a bare IP still resolve the
	// domain and match a domain rule.
	RouteOnly bool `json:"routeOnly"`
}

// Outbound is an egress path.
type Outbound struct {
	Tag      string            `json:"tag"`
	Protocol string            `json:"protocol"`
	Settings *OutboundSettings `json:"settings,omitempty"`
	Stream   *StreamSettings   `json:"streamSettings,omitempty"`
}

// OutboundSettings is protocol-specific outbound configuration.
type OutboundSettings struct {
	// Servers carries the socks/docks server list for the tunnel outbound.
	Servers []SocksServer `json:"servers,omitempty"`
	// DomainStrategy and UserLevel are used by the dns and direct outbounds.
	DomainStrategy string `json:"domainStrategy,omitempty"`
	UserLevel      int    `json:"userLevel,omitempty"`
}

// SocksServer is one upstream proxy endpoint.
type SocksServer struct {
	Address string `json:"address"`
	Port    int    `json:"port"`
}

// StreamSettings is the transport layer configuration, including the finalmask
// camouflage chain that this whole project exists to use.
type StreamSettings struct {
	Network   string     `json:"network,omitempty"`
	Security  string     `json:"security,omitempty"`
	Sockopt   *Sockopt   `json:"sockopt,omitempty"`
	FinalMask *FinalMask `json:"finalmask,omitempty"`
}

// Sockopt is the socket-level configuration.
type Sockopt struct {
	TCPKeepAliveInterval *int `json:"tcpKeepAliveInterval,omitempty"`
	TCPKeepAliveIdle     *int `json:"tcpKeepAliveIdle,omitempty"`
	// Interface pins the outbound to a named network interface. It is the
	// cheap half of the TUN loop mitigation: a direct outbound bound to the
	// physical NIC cannot be routed back into the tunnel by accident. It is
	// empty by default because it breaks when the user moves between WiFi and
	// ethernet, and the selective include routes already prevent the loop.
	Interface      string         `json:"interface,omitempty"`
	DomainStrategy string         `json:"domainStrategy,omitempty"`
	HappyEyeballs  *HappyEyeballs `json:"happyEyeballs,omitempty"`
	TCPFastOpen    *int           `json:"tfo,omitempty"`
}

// HappyEyeballs mirrors xray's happy-eyeballs sockopt.
type HappyEyeballs struct {
	TryDelayMs       int  `json:"tryDelayMs"`
	PrioritizeIPv6   bool `json:"prioritizeIPv6"`
	Interleave       int  `json:"interleave"`
	MaxConcurrentTry int  `json:"maxConcurrentTry"`
}

// FinalMask is the camouflage chain applied after the core has finished its own
// transport encryption. The first entry in each slice is the innermost layer.
type FinalMask struct {
	TCP []FinalMaskLayer `json:"tcp,omitempty"`
	UDP []FinalMaskLayer `json:"udp,omitempty"`
}

// FinalMaskLayer is one camouflage stage.
type FinalMaskLayer struct {
	Type string `json:"type"`
	// Settings is either FragmentSettings or NoiseSettings, chosen by Type.
	Settings any `json:"settings"`
}

// FragmentSettings controls outgoing TCP fragmentation.
type FragmentSettings struct {
	// Packets is "tlshello" to split the TLS ClientHello, or "1-1" to split
	// every packet.
	Packets string `json:"packets"`
	// Lengths are fragment sizes in bytes, each "n" or "a-b".
	Lengths []string `json:"lengths"`
	// Delays are inter-fragment delays in milliseconds, same "n"/"a-b" form.
	Delays []string `json:"delays"`
	// MaxSplit caps splits per packet, "n" or "a-b".
	MaxSplit string `json:"maxSplit"`
}

// NoiseSettings controls outgoing UDP camouflage.
type NoiseSettings struct {
	Reset string       `json:"reset"`
	Noise []noisePulse `json:"noise"`
}

// noisePulse is a single random-padding burst. It is redeclared here rather
// than reusing the model's type so the xray schema types carry no application
// concepts and can be checked against the upstream docs field by field.
type noisePulse struct {
	Random string `json:"rand"`
	Delay  string `json:"delay"`
}

// Routing selects an outbound per connection.
type Routing struct {
	// DomainStrategy is AsIs, not IPOnDemand: every rule here is already
	// domain-matched, so resolving each match again is pure added latency.
	DomainStrategy string        `json:"domainStrategy"`
	Rules          []RoutingRule `json:"rules"`
}

// RoutingRule is one ordered routing decision. Order is significant and is the
// part of this file most worth reading before editing: see
// internal/config/generator.go for the ladder.
type RoutingRule struct {
	OutboundTag string   `json:"outboundTag"`
	InboundTag  []string `json:"inboundTag,omitempty"`
	// Network is a comma-separated "tcp"/"udp" list.
	Network  string   `json:"network,omitempty"`
	Protocol []string `json:"protocol,omitempty"`
	// Port is always emitted as a string. The source configs mix forms ("53"
	// as a number in some rules, "443" as a string in others); xray's PortList
	// accepts either, so one consistent form is enough.
	Port   string   `json:"port,omitempty"`
	Domain []string `json:"domain,omitempty"`
	IP     []string `json:"ip,omitempty"`
}

// MarshalIndent renders the configuration the way it is written to disk, so a
// developer can diff a generated file against the source profile it came from.
func (c *XrayConfig) MarshalIndent() ([]byte, error) {
	return json.MarshalIndent(c, "", "  ")
}

// MarshalJSON renders any generated value as compact JSON, for handing to the
// core's loader.
func MarshalJSON(v any) ([]byte, error) { return json.Marshal(v) }
