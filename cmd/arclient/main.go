// Command arclient runs the engine.
//
// The graphical interface is a later phase. This entry point exists now because
// the engine and the selftest are the parts that have to be right, and having a
// second way to start the core means a fault can be reproduced without going
// through the UI.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"arclient/internal/config"
	"arclient/internal/engine"
	"arclient/internal/health"
	"arclient/internal/model"
	"arclient/internal/netcfg"
	"arclient/internal/store"
)

func main() {
	var (
		showConfig  = flag.Bool("show-config", false, "print the generated core config and exit")
		showTOML    = flag.Bool("show-zeptun", false, "print the generated tunnel config and exit")
		probe       = flag.Bool("probe", false, "probe the routes and exit")
		withTunnel  = flag.Bool("tunnel", false, "also start Aether and probe through it")
		rawConfig   = flag.String("raw-config", "", "run this JSON config verbatim instead of a generated one (for A/B against an upstream reference)")
		aetherPeer  = flag.String("aether-peer", "", "pin the Aether gateway as ip:port and skip the scan")
		aetherProto = flag.String("aether-protocol", "", "masque, wg, gool, tor or psiphon")
		aetherH2    = flag.Bool("aether-h2", false, "carry MASQUE over HTTP/2 instead of HTTP/3")
		hold        = flag.Duration("hold", 0, "exit automatically after this long; 0 waits for Ctrl-C")
		useProxy    = flag.Bool("system-proxy", false, "point the Windows system proxy at the core while running, and restore it on exit")
		kill        = flag.Bool("off", false, "turn the system proxy off and exit; the panic path")
	)
	flag.Parse()

	// The panic path deliberately bypasses everything else. It is the one command
	// that has to work when nothing else does, so it must not depend on the
	// configuration being valid, on a port being free, or on the core starting.
	if *kill {
		if err := netcfg.Clear(); err != nil {
			fatal("%v", err)
		}
		fmt.Println("system proxy cleared.")
		return
	}

	st, err := store.Open()
	if err != nil {
		fatal("%v", err)
	}
	cfg, err := st.Load()
	if err != nil {
		fatal("%v", err)
	}
	cfg.Normalize()
	if err := cfg.Validate(); err != nil {
		fatal("%v", err)
	}

	if *showConfig {
		x, err := config.Generate(cfg, config.Options{LogLevel: "info"})
		if err != nil {
			fatal("%v", err)
		}
		b, err := x.MarshalIndent()
		if err != nil {
			fatal("%v", err)
		}
		fmt.Println(string(b))
		return
	}
	if *showTOML {
		toml, err := config.ZeptunTOML(cfg, config.ZeptunOptions{})
		if err != nil {
			fatal("%v", err)
		}
		fmt.Println(toml)
		return
	}

	// Conflicts are reported and not treated as fatal: the generator resolves
	// them deterministically, so the configuration still runs. Silently running
	// with one of two rules inert is worse than a warning.
	for _, c := range config.Conflicts(cfg) {
		fmt.Fprintf(os.Stderr, "warning: %s\n", c)
	}

	xr := engine.New()
	if *rawConfig != "" {
		raw, err := os.ReadFile(*rawConfig)
		if err != nil {
			fatal("%v", err)
		}
		if err := xr.StartRaw(raw, filepath.Join(st.Dir(), "geo")); err != nil {
			fatal("%v", err)
		}
	} else if err := xr.Start(cfg, config.Options{LogLevel: "info"}, filepath.Join(st.Dir(), "geo")); err != nil {
		fatal("%v", err)
	}
	defer xr.Stop()
	addr := xr.Addr()
	if err := xr.WaitReady(addr, 10*time.Second); err != nil {
		fatal("%v", err)
	}
	fmt.Printf("core listening on %s\n", addr)

	// Dump the exact document the core was started from. When something is not
	// working, the first question is what the core was actually told.
	if p, err := engine.WriteGeneratedConfig(st.Dir(), xr.GeneratedConfig()); err == nil {
		fmt.Printf("generated config: %s\n", p)
	}

	// The tunnel is started when asked for, and also whenever a rule actually
	// needs it. Probing the tunnel with no tunnel rules in the configuration
	// would report "no rules, skipping" even when the user explicitly asked for
	// it, which reads as a refusal rather than as nothing to do.
	var aether *engine.Aether
	tunnelRules := hasTunnelRules(cfg)
	if *withTunnel && !tunnelRules {
		fmt.Println("no tunnel rules configured; probing the tunnel anyway because --tunnel was given")
	}
	if tunnelRules || *withTunnel {
		a, err := engine.NewAether(binaryDir(), filepath.Join(st.Dir(), "aether"))
		if err != nil {
			fmt.Fprintf(os.Stderr, "aether unavailable: %v\n", err)
			if !*withTunnel {
				return
			}
		} else {
			settings := engine.DefaultAetherSettings()
			if *aetherPeer != "" {
				settings.Peer = *aetherPeer
			}
			if *aetherProto != "" {
				settings.Protocol = engine.AetherProtocol(*aetherProto)
			}
			if *aetherH2 {
				settings.HTTP2 = true
			}
			if err := settings.Validate(); err != nil {
				fatal("%v", err)
			}
			fmt.Printf("starting Aether: %s peer=%s\n", settings.Protocol, orDash(settings.Peer))

			if err := a.Start(context.Background(), settings); err != nil {
				fmt.Fprintf(os.Stderr, "aether failed to start: %v\n", err)
				if !*withTunnel {
					return
				}
			} else {
				aether = a
				addr := fmt.Sprintf("127.0.0.1:%d", cfg.AetherPort)
				fmt.Printf("waiting for %s (Aether holds the port closed until real data passes)\n", addr)
				if err := a.WaitReady(addr, 120*time.Second); err != nil {
					fmt.Fprintf(os.Stderr, "aether did not come up: %v\n", err)
					drainAether(a)
				} else {
					fmt.Println("aether ready")
				}
			}
		}
	}

	go func() {
		for line := range logLines(aether) {
			fmt.Println("  | " + line)
		}
	}()

	// Capture. Without this the core listens on loopback and nothing connects,
	// which looks exactly like the traffic being filtered and is not.
	//
	// The previous state is read before anything is changed, and restored on
	// every exit path including a crash signal, because a system proxy pointing
	// at a listener that no longer exists leaves the machine unable to reach
	// anything through any proxy-aware application.
	var restoreProxy func()
	if *useProxy {
		previous, err := netcfg.Read()
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not read the current proxy settings: %v\n", err)
		}
		if err := netcfg.Set(addr); err != nil {
			fatal("set system proxy: %v", err)
		}
		fmt.Printf("system proxy -> %s  (was %s)\n", addr, netcfg.Describe(previous))
		restoreProxy = func() {
			if err := netcfg.Restore(previous); err != nil {
				fmt.Fprintf(os.Stderr, "warning: could not restore the system proxy: %v\n", err)
				fmt.Fprintf(os.Stderr, "run:  ARClient.exe --off\n")
				return
			}
			fmt.Printf("system proxy restored to %s\n", netcfg.Describe(previous))
		}
		// Declared after the core's own shutdown, so it runs first: the proxy
		// must never point at a listener that has already closed, not even for
		// the moment between the two.
		defer restoreProxy()
	}

	if *probe {
		printProbe(cfg, addr, aether)
		return
	}

	if *hold > 0 {
		fmt.Printf("running for %s, then exiting.\n", *hold)
		time.Sleep(*hold)
		fmt.Println("stopping")
		return
	}
	fmt.Println("running. Ctrl-C to stop.")
	waitForInterrupt(restoreProxy)
}

// waitForInterrupt blocks until the user asks to stop.
//
// The restore runs on the signal path as well as through the deferred call,
// because a process killed with Ctrl-C that skips it leaves the machine's proxy
// pointing at a listener that has just gone away. Doing the restore in both
// places is harmless — the second is a no-op — while missing it in either is an
// outage.
func waitForInterrupt(restore func()) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	<-ch
	fmt.Println("\nstopping")
	if restore != nil {
		restore()
	}
}

// drainAether prints whatever the child produced, so a failure is diagnosable
// without re-running it attached.
func drainAether(a *engine.Aether) {
	deadline := time.After(2 * time.Second)
	for {
		select {
		case line := <-a.LogLines():
			fmt.Println("  | " + line)
		case <-deadline:
			return
		}
	}
}

// logLines returns Aether's output, or a channel that never fires when Aether
// is not running, so the caller does not need to special-case it.
func logLines(a *engine.Aether) <-chan string {
	if a == nil {
		return make(chan string)
	}
	return a.LogLines()
}

func printProbe(cfg *model.Config, addr string, aether *engine.Aether) {
	direct := health.Probe(context.Background(), "", 25*time.Second)
	fmt.Printf("direct  %s\n", direct)

	frag := health.Probe(context.Background(), addr, 25*time.Second)
	fmt.Printf("frag    %s\n", frag)
	if frag.Reachable && direct.Reachable {
		if frag.IsLocalExit(direct) {
			fmt.Println("        -> frag preserves your real IP")
		} else {
			fmt.Printf("        -> frag exits elsewhere (%s vs %s)\n", frag.ExitIP, direct.ExitIP)
		}
	}
	if aether == nil {
		return
	}

	// Whether the tunnel will carry UDP decides whether voice can be routed
	// through it at all, so it is reported before the tunnel is probed rather
	// than as a separate exercise.
	tunnelAddr := fmt.Sprintf("127.0.0.1:%d", cfg.AetherPort)
	ua := health.ProbeUDPAssociate(tunnelAddr, 10*time.Second)
	if ua.Supported {
		fmt.Printf("udp     tunnel accepts UDP (relay %s)\n", ua.RelayAddr)
	} else {
		fmt.Printf("udp     tunnel will NOT carry UDP: %v\n", ua.Err)
	}

	tun := health.Probe(context.Background(), tunnelAddr, 25*time.Second)
	fmt.Printf("tunnel  %s\n", tun)
	if tun.Reachable && direct.Reachable {
		if tun.IsLocalExit(direct) {
			fmt.Println("        -> tunnel also presents your real IP")
		} else {
			fmt.Printf("        -> tunnel exits elsewhere (%s, country %s). Services that\n"+
				"           refuse Iranian addresses will fail on this route.\n", tun.ExitIP, orDash(tun.ExitISO))
		}
	}
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func hasTunnelRules(cfg *model.Config) bool {
	for _, r := range cfg.Rules {
		if r.Enabled && r.EffectiveMode() == model.ModeTunnel {
			return true
		}
	}
	return false
}

func binaryDir() string {
	if exe, err := os.Executable(); err == nil {
		return filepath.Dir(exe)
	}
	return "."
}

func fatal(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "arclient: "+format+"\n", a...)
	os.Exit(1)
}
