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
	"arclient/internal/store"
)

func main() {
	var (
		showConfig = flag.Bool("show-config", false, "print the generated core config and exit")
		showTOML   = flag.Bool("show-zeptun", false, "print the generated tunnel config and exit")
		probe      = flag.Bool("probe", false, "probe the running route and exit")
		withTunnel = flag.Bool("tunnel", false, "also start Aether")
		rawConfig  = flag.String("raw-config", "", "run this JSON config verbatim instead of a generated one (for A/B against an upstream reference)")
	)
	flag.Parse()

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

	var aether *engine.Aether
	if *withTunnel {
		if hasTunnelRules(cfg) {
			a, err := engine.NewAether(binaryDir(), filepath.Join(st.Dir(), "aether"))
			if err != nil {
				fatal("%v", err)
			}
			if err := a.Start(context.Background(), engine.DefaultAetherSettings()); err != nil {
				fatal("%v", err)
			}
			defer a.Stop(5 * time.Second)
			aether = a
			fmt.Println("starting Aether...")
		} else {
			fmt.Println("no tunnel rules configured; not starting Aether")
		}
	}

	go func() {
		for line := range logLines(aether) {
			fmt.Println("  | " + line)
		}
	}()

	if *probe {
		printProbe(cfg, addr)
		return
	}

	fmt.Println("running. Ctrl-C to stop.")
	waitForInterrupt()
}

// logLines returns Aether's output, or a channel that never fires when Aether
// is not running, so the caller does not need to special-case it.
func logLines(a *engine.Aether) <-chan string {
	if a == nil {
		return make(chan string)
	}
	return a.LogLines()
}

func printProbe(cfg *model.Config, addr string) {
	direct := health.Probe(context.Background(), "", 20*time.Second)
	fmt.Printf("direct  %s\n", direct)
	frag := health.Probe(context.Background(), addr, 20*time.Second)
	fmt.Printf("frag    %s\n", frag)
	if frag.Reachable && direct.Reachable {
		if frag.IsLocalExit(direct) {
			fmt.Println("        -> frag preserves your real IP")
		} else {
			fmt.Printf("        -> frag exits elsewhere (%s vs %s)\n", frag.ExitIP, direct.ExitIP)
		}
	}
}

func waitForInterrupt() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	<-ch
	fmt.Println("\nstopping")
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
