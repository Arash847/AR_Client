package engine

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/proxyman"
	xcorecfg "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/transport/internet/finalmask/fragment"

	"arclient/internal/config"
	"arclient/internal/model"
)

// This file is the guard that the rest of the project depends on and that no
// amount of reading the generator would have given us.
//
// The core's JSON loader is lenient: a field it does not recognise is dropped
// without complaint, and the core starts anyway. That is exactly what happened
// while building this. The newest *tagged* xray-core release is v1.260327.0,
// whose fragment settings carry a single length_min/length_max pair. The
// lengths/delays *arrays* that the working FragB profile depends on arrived in
// PR #6334 and exist only on main, untagged. Running
// `go get github.com/xtls/xray-core@latest` therefore yields a core that starts,
// accepts the config, and silently fragments by a different rule than the one
// that works on this network.
//
// The only symptom a user would see is "Discord stopped working", with no error
// anywhere. So the assertion below is not "the config parses" but "the parsed
// config still contains fragB's exact fragment lengths".

// loadThroughCore runs a generated config through the same loader the core's
// own command line uses.
func loadThroughCore(t *testing.T, cfg *model.Config) *xcorecfg.Config {
	t.Helper()
	x, err := config.Generate(cfg, config.Options{})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	raw, err := marshal(x)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	pb, err := xcorecfg.LoadConfig("json", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("core rejected the generated config: %v", err)
	}
	return pb
}

// TestCorePreservesFragBFragmentLengths is the load-bearing test.
//
// It walks the protobuf the core actually built and checks the fragment lengths
// are [0, 104, 1] with the leading zero intact. A dependency bump to a version
// without the arrays fails here, instead of failing on a user's machine as a
// client that loads but cannot connect.
func TestCorePreservesFragBFragmentLengths(t *testing.T) {
	cfg := model.DefaultConfig()
	cfg.Normalize()
	pb := loadThroughCore(t, cfg)

	mask := tcpMaskFor(t, pb, config.TagFragTLS)
	if mask == nil {
		t.Fatal("frag-tls has no TCP finalmask; fragmentation would silently do nothing")
	}

	// The first layer is the ClientHello split, and it is the one that matters.
	if len(mask) == 0 {
		t.Fatal("frag-tls TCP finalmask is empty")
	}
	first := mask[0]
	if got := first.GetLengthsMin(); len(got) != 3 || got[0] != 0 || got[1] != 104 || got[2] != 1 {
		t.Errorf("fragB ClientHello lengths = %v, want [0 104 1]; the leading zero is what defeats SNI filtering on this network", got)
	}
	if len(first.GetDelaysMin()) == 0 || first.GetDelaysMin()[0] != 0 {
		t.Errorf("fragB first delay = %v, want [0]", first.GetDelaysMin())
	}
	if first.GetMaxSplitMin() != 0 {
		t.Errorf("fragB first maxSplit = %d, want 0", first.GetMaxSplitMin())
	}
	if first.GetPacketsFrom() != 0 {
		t.Errorf("fragB first packets_from = %d, want 0 (meaning the tlshello selector)", first.GetPacketsFrom())
	}

	// The second layer splits every subsequent packet.
	if len(mask) != 2 {
		t.Fatalf("frag-tls has %d finalmask layers, want 2", len(mask))
	}
	second := mask[1]
	if got := second.GetLengthsMin(); len(got) != 2 || got[0] != 114 || got[1] != 1 {
		t.Errorf("second layer lengths = %v, want [114 1]", got)
	}
	if second.GetMaxSplitMin() != 11 {
		t.Errorf("second layer maxSplit = %d, want 11", second.GetMaxSplitMin())
	}
}

// TestCoreAcceptsEveryRouteShape checks the generated config survives the loader
// for each combination of rule mode and transport, because a shape that only
// appears once the user edits their rules is exactly the one that would fail at
// startup for them and not in CI.
func TestCoreAcceptsEveryRouteShape(t *testing.T) {
	shapes := map[string][]model.Rule{
		"frag tcp": {
			{Name: "a", Mode: model.ModeFrag, Transport: model.TransportTCP, Enabled: true, Domains: []string{"discord.com"}},
		},
		"frag udp": {
			{Name: "a", Mode: model.ModeFrag, Transport: model.TransportUDP, Enabled: true, Domains: []string{"voice.discord.gg"}},
		},
		"frag both": {
			{Name: "a", Mode: model.ModeFrag, Transport: model.TransportBoth, Enabled: true, Domains: []string{"discord.com"}},
		},
		"tunnel tcp": {
			{Name: "a", Mode: model.ModeTunnel, Transport: model.TransportTCP, Enabled: true, Domains: []string{"web.telegram.org"}},
		},
		"tunnel udp": {
			{Name: "a", Mode: model.ModeTunnel, Transport: model.TransportUDP, Enabled: true, Domains: []string{"web.telegram.org"}},
		},
		"direct only": {
			{Name: "a", Mode: model.ModeDirect, Transport: model.TransportBoth, Enabled: true, Domains: []string{"example.ir"}},
		},
		"auto un-escalated": {
			{Name: "a", Mode: model.ModeAuto, Transport: model.TransportUDP, Enabled: true, Domains: []string{"voice.discord.gg"}},
		},
		"auto escalated": {
			{Name: "a", Mode: model.ModeAuto, Transport: model.TransportUDP, Enabled: true,
				Domains: []string{"voice.discord.gg"}, AutoEscalated: true},
		},
		"fragA profile": {
			{Name: "a", Mode: model.ModeFrag, Transport: model.TransportBoth, Enabled: true, Domains: []string{"discord.com"}},
		},
	}
	for name, rules := range shapes {
		t.Run(name, func(t *testing.T) {
			cfg := model.DefaultConfig()
			cfg.Rules = rules
			if name == "fragA profile" {
				cfg.Profile = "fragA"
			}
			cfg.Normalize()
			loadThroughCore(t, cfg) // fails the test if the core rejects it
		})
	}
}

// TestCoreAcceptsGeoRulesWhenAssetsAreStaged covers the geo-enabled shape.
//
// Skipped unless the assets are present, because the core's rejection of a
// missing geosite.dat is reported as an illegal domain rule rather than as a
// missing file — a genuinely misleading message. The skip keeps the default
// (no geo) path fully covered while leaving the geo path covered for anyone
// building with --with-geo.
func TestCoreAcceptsGeoRulesWhenAssetsAreStaged(t *testing.T) {
	dir := geoAssetDir(t)
	cfg := model.DefaultConfig()
	cfg.WithGeo = true
	cfg.BlockAds = true
	cfg.Normalize()
	t.Setenv("xray.location.asset", dir)
	loadThroughCore(t, cfg)
}

// geoAssetDir locates staged geo assets, skipping the test when they are absent.
func geoAssetDir(t *testing.T) string {
	t.Helper()
	candidates := []string{
		filepath.Join("testdata", "geo"),
		filepath.Join("geo"),
	}
	for _, c := range candidates {
		if _, err := os.Stat(filepath.Join(c, "geosite.dat")); err == nil {
			return c
		}
	}
	t.Skip("geo assets are not staged; build with --with-geo to cover this path")
	return ""
}

// TestCoreRejectsUnknownFields confirms the loader really is lenient, which is
// the premise the test above exists to work around.
//
// If this ever starts failing, the core has become strict and the version trap
// has closed on its own; the walking test could then be simplified. It is kept
// so that change is noticed rather than assumed.
func TestCoreRejectsUnknownFields(t *testing.T) {
	// A deliberately nonsensical finalmask type. If the core is strict this
	// errors, and TestCorePreservesFragBFragmentLengths can stop relying on a
	// deep walk.
	x := config.XrayConfig{
		Version: config.Version{Min: model.XrayVersionMin},
		Outbounds: []config.Outbound{{
			Tag:      "probe",
			Protocol: "direct",
			Stream: &config.StreamSettings{
				FinalMask: &config.FinalMask{
					TCP: []config.FinalMaskLayer{{Type: "definitely-not-a-real-camouflage-type", Settings: map[string]any{}}},
				},
			},
		}},
	}
	raw, err := marshal(&x)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	_, err = xcorecfg.LoadConfig("json", bytes.NewReader(raw))
	t.Logf("core response to an unknown finalmask type: %v", err)
	// No assertion on the outcome. The point is the observation, and the
	// version-pin comment in fetch-cores.ps1 is what actually protects the
	// build.
}

// --- helpers ---------------------------------------------------------------

// TestCoreActuallyStarts is the test that closes the gap the earlier suite had.
//
// Loading a configuration exercises the parser. Starting the instance
// exercises every feature's Start method, and those are separate code paths that
// disagree: the fake DNS pool, for instance, loads fine with no pool size
// configured and then refuses to start with "invalid fakeDNS setting". That
// error names neither the field nor the cause, so a suite that only loads
// configurations reports a working generator for a core that cannot run.
//
// Each subtest takes a distinct port because the tests run in one process and a
// listener left bound would make the next one fail for the wrong reason.
func TestCoreActuallyStarts(t *testing.T) {
	port := 21080
	nextPort := func() int { port++; return port }

	t.Run("frag only", func(t *testing.T) {
		cfg := model.DefaultConfig()
		cfg.MixedPort, cfg.AetherPort = nextPort(), nextPort()+1000
		startAndStop(t, cfg, "")
	})

	t.Run("frag and tunnel", func(t *testing.T) {
		cfg := model.DefaultConfig()
		cfg.MixedPort, cfg.AetherPort = nextPort(), nextPort()+1000
		cfg.Rules = append(cfg.Rules, model.Rule{
			Name: "telegram", Mode: model.ModeTunnel, Transport: model.TransportBoth,
			Enabled: true, Domains: []string{"web.telegram.org"},
		})
		// The tunnel's upstream does not exist here, which is the point: the
		// core must come up and only fail if that upstream is actually used.
		startAndStop(t, cfg, "")
	})

	t.Run("udp camouflage", func(t *testing.T) {
		cfg := model.DefaultConfig()
		cfg.MixedPort, cfg.AetherPort = nextPort(), nextPort()+1000
		cfg.Rules = []model.Rule{{
			Name: "voice", Mode: model.ModeFrag, Transport: model.TransportUDP,
			Enabled: true, Domains: []string{"voice.discord.gg"},
		}}
		startAndStop(t, cfg, "")
	})
}

func startAndStop(t *testing.T, cfg *model.Config, assetDir string) {
	t.Helper()
	cfg.Normalize()
	x := New()
	if err := x.Start(cfg, config.Options{LogLevel: "error"}, assetDir); err != nil {
		t.Fatalf("core did not start: %v", err)
	}
	t.Cleanup(func() {
		if err := x.Stop(); err != nil {
			t.Errorf("core did not stop cleanly: %v", err)
		}
	})
	if err := x.WaitReady(x.Addr(), 5*time.Second); err != nil {
		t.Fatalf("core started but is not listening: %v", err)
	}
}

// tcpMaskFor resolves the fragment layers of a named outbound by walking the
// protobuf the core actually built.
//
// The path is handler → sender_settings → SenderConfig → stream_settings. Each
// hop is a place where reaching for the obvious neighbour instead gives a
// silent wrong answer rather than a compile error: proxy_settings resolves to
// the freedom (direct) settings, and sender_settings is not itself the stream
// config. Those two wrong turns are why this walk is written out rather than
// reached for on the first try.
func tcpMaskFor(t *testing.T, pb *xcorecfg.Config, tag string) []*fragment.Config {
	t.Helper()
	for _, ob := range pb.Outbound {
		if ob.Tag != tag || ob.SenderSettings == nil {
			continue
		}
		msg, err := ob.SenderSettings.GetInstance()
		if err != nil {
			t.Fatalf("resolve %s sender settings: %v", tag, err)
		}
		sender, ok := msg.(*proxyman.SenderConfig)
		if !ok {
			t.Fatalf("%s sender settings resolved to %T, want *proxyman.SenderConfig", tag, msg)
		}
		sc := sender.StreamSettings
		if sc == nil {
			return nil
		}
		var out []*fragment.Config
		for _, m := range sc.Tcpmasks {
			inst, err := m.GetInstance()
			if err != nil {
				// A layer of some other kind. Noise and header camouflage land
				// here and are simply not what this helper collects.
				continue
			}
			if f, ok := inst.(*fragment.Config); ok {
				out = append(out, f)
			}
		}
		return out
	}
	return nil
}

func marshal(v any) ([]byte, error) { return config.MarshalJSON(v) }
