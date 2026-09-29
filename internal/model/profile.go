package model

// Fragmentation presets, seeded verbatim from @patterniha's Serverless-for-Iran
// configs. These values are the reason this project works on this network, so
// they are data the user can edit rather than constants buried in the
// generator. The working split offset is network-specific and will drift as the
// upstream filter changes.

// XrayVersionMin is the xray-core version floor the source configs declare. The
// fragment finalmask's lengths/delays arrays arrived in XTLS/Xray-core PR #6334,
// authored by @patterniha, so this floor is not negotiable.
const XrayVersionMin = "26.6.27"

// FragmentStep is one layer of the TCP finalmask chain.
type FragmentStep struct {
	// Packet selects what to fragment: "tlshello" for the TLS ClientHello, or
	// "1-1" to split every packet.
	Packet string `json:"packets"`
	// Lengths are the fragment sizes in bytes, each either "n" or "a-b".
	Lengths []string `json:"lengths"`
	// Delays are the inter-fragment delays in milliseconds, same "n"/"a-b" form.
	Delays []string `json:"delays"`
	// MaxSplit caps how many times a packet may be split, "n" or "a-b".
	MaxSplit string `json:"maxSplit"`
}

// NoisePulse is one burst of random UDP padding.
type NoisePulse struct {
	// Random is a padded size range in bytes, "a-b".
	Random string `json:"rand"`
	// Delay is milliseconds to wait after the burst.
	Delay string `json:"delay"`
}

// NoiseStep is the UDP camouflage layer.
type NoiseStep struct {
	// Reset is the payload size, in bytes, at which the peer resets state.
	Reset string       `json:"reset"`
	Noise []NoisePulse `json:"noise"`
}

// HappyEyeballs mirrors xray's sockopt.happyEyeballs.
//
// prioritizeIPv6 is false because a half-working IPv6 path makes clients stall
// on a fallback timer instead of failing fast, which reads to the user as
// "Discord is slow" rather than as a network fault.
type HappyEyeballs struct {
	TryDelayMS       int  `json:"tryDelayMs"`
	PrioritizeIPv6   bool `json:"prioritizeIPv6"`
	Interleave       int  `json:"interleave"`
	MaxConcurrentTry int  `json:"maxConcurrentTry"`
}

// Profile is one complete fragmentation preset.
type Profile struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Source     string `json:"source"`
	VersionMin string `json:"versionMin"`
	// Recommended marks the profile the app selects by default. Exactly one
	// profile should set it.
	Recommended bool `json:"recommended"`
	// Note explains, in the user's terms, why this profile is or is not the
	// one that works. Shown in the UI.
	Note          string         `json:"note,omitempty"`
	TCPTLS        []FragmentStep `json:"tcpFragmentTLS"`
	TCP           []FragmentStep `json:"tcpFragment"`
	UDPNoise      *NoiseStep     `json:"udpNoise,omitempty"`
	HappyEyeballs HappyEyeballs  `json:"happyEyeballs"`
}

// UDPNoisePulses is the burst count in the source configs. Kept as a named
// constant because the count, not just the values, is part of the working
// pattern.
const UDPNoisePulses = 22

// defaultHappyEyeballs returns the sockopt shared by both source profiles.
func defaultHappyEyeballs() HappyEyeballs {
	return HappyEyeballs{
		TryDelayMS:       300,
		PrioritizeIPv6:   false,
		Interleave:       4,
		MaxConcurrentTry: 20,
	}
}

// DefaultProfiles returns the shipped presets.
//
// fragB is recommended because it is the one that works on this network: its
// first ClientHello fragment has length "0", so the split lands before a usable
// SNI-bearing record reaches the wire. fragA splits 6 bytes in, which is
// detectable here. fragA is kept only as an editable variant.
func DefaultProfiles() map[string]Profile {
	return map[string]Profile{
		"fragB": {
			ID:          "fragB",
			Name:        "FragB (recommended)",
			Source:      "https://github.com/patterniha/Serverless-for-Iran/blob/main/Serverless-fragB.jsonc",
			VersionMin:  XrayVersionMin,
			Recommended: true,
			Note: "Opens the ClientHello split with a zero-length fragment, so no " +
				"single packet on the wire carries a complete SNI. This is the " +
				"profile that works on this network.",
			TCPTLS: []FragmentStep{
				// The two halves that matter. The leading "0" is the whole
				// reason fragB beats fragA here; "104" is only meaningful in
				// combination with the other settings, so treat the pairing as
				// the unit and not the number as a constant to tune alone.
				{Packet: "tlshello", Lengths: []string{"0", "104", "1"}, Delays: []string{"0"}, MaxSplit: "0"},
				{Packet: "1-1", Lengths: []string{"114", "1"}, Delays: []string{"1"}, MaxSplit: "11"},
			},
			TCP: []FragmentStep{
				{Packet: "1-1", Lengths: []string{"1"}, Delays: []string{"1"}, MaxSplit: "201"},
			},
			UDPNoise:      defaultNoise(),
			HappyEyeballs: defaultHappyEyeballs(),
		},
		"fragA": {
			ID:          "fragA",
			Name:        "FragA (variant)",
			Source:      "https://github.com/patterniha/Serverless-for-Iran/blob/main/Serverless-fragA.jsonc",
			VersionMin:  XrayVersionMin,
			Recommended: false,
			Note: "Splits the ClientHello 6 bytes in rather than at zero. " +
				"Detected on this network, so it is a variant to fall back to, " +
				"not an alternative.",
			TCPTLS: []FragmentStep{
				{Packet: "tlshello", Lengths: []string{"6", "98", "1"}, Delays: []string{"0"}, MaxSplit: "0"},
				{Packet: "1-1", Lengths: []string{"114", "1"}, Delays: []string{"1"}, MaxSplit: "11"},
			},
			TCP: []FragmentStep{
				{Packet: "1-1", Lengths: []string{"1"}, Delays: []string{"1"}, MaxSplit: "201"},
			},
			UDPNoise:      defaultNoise(),
			HappyEyeballs: defaultHappyEyeballs(),
		},
	}
}

// defaultNoise returns the 22-pulse UDP camouflage burst from the source
// configs: 1200-1230 bytes of random padding, 10 ms apart, resetting at 28
// bytes of real payload.
func defaultNoise() *NoiseStep {
	n := &NoiseStep{Reset: "28", Noise: make([]NoisePulse, 0, UDPNoisePulses)}
	for i := 0; i < UDPNoisePulses; i++ {
		n.Noise = append(n.Noise, NoisePulse{Random: "1200-1230", Delay: "10"})
	}
	return n
}
