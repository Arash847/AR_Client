// Command selftest answers the questions that cannot be settled without running
// on the target network.
//
// It exists because CI cannot test any of this from inside Iran, and because
// four of the design decisions are empirical. Each gate below is a decision
// that changes what gets built, and each is cheap to answer here and expensive
// to answer later by debugging.
//
// The output is written to be pasted into an issue. A report that cannot be
// pasted is a report nobody sends.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"arclient/internal/config"
	"arclient/internal/discovery"
	"arclient/internal/engine"
	"arclient/internal/health"
	"arclient/internal/model"
	"arclient/internal/store"
)

func main() {
	var (
		jsonOut  = flag.String("json", "", "also write the machine-readable report to this path")
		noTunnel = flag.Bool("no-tunnel", false, "skip starting Aether and the tunnel gates (frag-only run)")
		timeout  = flag.Duration("timeout", 45*time.Second, "per-probe timeout")
		dumpCfg  = flag.Bool("dump-config", true, "write the generated core config for inspection")
		access   = flag.String("access-log", "", "an existing access log to analyse instead of probing")
	)
	flag.Parse()

	r := &Report{
		StartedAt: time.Now(),
		Version:   "0.1.0-phase1",
	}

	st, err := store.Open()
	if err != nil {
		fatal("open store: %v", err)
	}
	cfg, err := st.Load()
	if err != nil {
		fatal("load config: %v", err)
	}
	cfg.Normalize()
	if err := cfg.Validate(); err != nil {
		fatal("config is invalid:\n%v", err)
	}
	r.ConfigPath = st.Path()
	r.Profile = cfg.Profile

	printHeader(r, cfg)

	// --- configuration checks, which need no network at all -----------------
	r.Checks = append(r.Checks, checkVersionGate(cfg))
	r.Checks = append(r.Checks, checkConflicts(cfg))
	r.Checks = append(r.Checks, checkSharedPool(cfg))
	r.Checks = append(r.Checks, checkKeepAlive(cfg))
	if r.HasFailure() {
		// Configuration problems make every network result meaningless, and
		// reporting them alongside probes produces a long report that buries
		// the one line that matters.
		finish(r, *jsonOut, *dumpCfg, nil)
		return
	}

	// --- direct baseline ----------------------------------------------------
	// Taken first and without any proxy, because every "preserves my real IP"
	// answer is a comparison against it. If this fails, those answers are
	// vacuously true and the report has to say so.
	fmt.Println("\n[0] Direct baseline (no proxy) — the comparison every claim is measured against")
	direct := health.Probe(context.Background(), "", *timeout)
	r.Direct = &direct
	fmt.Printf("    %s\n", direct)
	if !direct.Reachable {
		fmt.Println("    NOTE: the direct baseline failed. Either the network is offline, or an")
		fmt.Println("    existing VPN or proxy is intercepting. Exit-IP comparisons below cannot be")
		fmt.Println("    trusted until this succeeds.")
	}

	// --- start the core -----------------------------------------------------
	fmt.Printf("\n[1] Starting the core (profile %s)\n", cfg.Profile)
	xr := engine.New()
	opts := config.Options{LogLevel: "info"}
	if err := xr.Start(cfg, opts, assetDir(st)); err != nil {
		r.Checks = append(r.Checks, Check{Name: "core starts", Pass: false, Detail: err.Error()})
		finish(r, *jsonOut, *dumpCfg, nil)
		return
	}
	r.Checks = append(r.Checks, Check{Name: "core starts", Pass: true, Detail: "core loaded the generated config"})
	addr := xr.Addr()
	if err := xr.WaitReady(addr, 10*time.Second); err != nil {
		r.Checks = append(r.Checks, Check{Name: "core listener ready", Pass: false, Detail: err.Error()})
		_ = xr.Stop()
		finish(r, *jsonOut, *dumpCfg, nil)
		return
	}
	r.Checks = append(r.Checks, Check{Name: "core listener ready", Pass: true, Detail: addr})
	defer xr.Stop()

	// --- G3, through the core (frag) ----------------------------------------
	fmt.Println("\n[G3] Exit address through the core (frag path)")
	frag := health.Probe(context.Background(), addr, *timeout)
	r.Frag = &frag
	fmt.Printf("    %s\n", frag)
	if frag.Reachable && direct.Reachable {
		same := frag.IsLocalExit(direct)
		r.FragPreservesRealIP = &same
		if same {
			fmt.Println("    -> matches the direct address, so this route preserves your real IP")
		} else {
			fmt.Printf("    -> differs from the direct address (%s vs %s).\n", frag.ExitIP, direct.ExitIP)
			if frag.WARP == "on" {
				fmt.Println("       WARP is on, so this is a Cloudflare exit, not a local one.")
			}
		}
	} else {
		fmt.Println("    -> the frag path is unreachable, so no comparison is possible.")
	}

	// --- G1 and G3, through the tunnel --------------------------------------
	var aetherAddr string
	if *noTunnel {
		fmt.Println("\n[G1/G3] Skipped (--no-tunnel)")
	} else if !hasTunnelRules(cfg) {
		fmt.Println("\n[G1/G3] Skipped: no rule is in tunnel mode, so Aether is not needed.")
		fmt.Println("       Add a rule with mode \"tunnel\" to exercise this path.")
	} else {
		fmt.Println("\n[G1] Does the tunnel carry UDP? (decides whether voice can be tunnelled at all)")
		a, err := engine.NewAether(binaryDir(st), filepath.Join(st.Dir(), "aether"))
		if err != nil {
			r.Checks = append(r.Checks, Check{Name: "locate aether", Pass: false, Detail: err.Error()})
		} else {
			aetherAddr = "127.0.0.1:" + itoa(cfg.AetherPort)
			if err := a.Start(context.Background(), engine.DefaultAetherSettings()); err != nil {
				r.Checks = append(r.Checks, Check{Name: "start aether", Pass: false, Detail: err.Error()})
			} else {
				fmt.Printf("    waiting for %s (Aether holds the port closed until real data passes)\n", aetherAddr)
				if err := a.WaitReady(aetherAddr, 90*time.Second); err != nil {
					r.Checks = append(r.Checks, Check{Name: "aether ready", Pass: false, Detail: err.Error()})
					fmt.Println("    aether did not come up. Its output follows:")
					drainLogs(a, 40)
				} else {
					r.Checks = append(r.Checks, Check{Name: "aether ready", Pass: true, Detail: aetherAddr})
					fmt.Println("    ready")
					probeTunnel(r, aetherAddr, direct, *timeout)
				}
				_ = a.Stop(5 * time.Second)
			}
		}
	}

	// --- G2 -----------------------------------------------------------------
	fmt.Println("\n[G2] Can UDP leave this machine at all? (decides whether voice needs anything)")
	udp := health.ProbeUDPEgress(context.Background(), "pool.ntp.org", 3*time.Second)
	r.UDP = &udp
	switch {
	case udp.Conclusive && udp.Works:
		fmt.Printf("    yes, %dms round trip\n", udp.RTT.Milliseconds())
		fmt.Println("    -> Discord voice very likely works unproxied. Voice uses ports ~50000-65535,")
		fmt.Println("       not 443, so the QUIC block does not affect it.")
	case udp.Err != nil:
		fmt.Printf("    inconclusive: %v\n", udp.Err)
		fmt.Println("    -> a silent server and a filtered network look identical from here. Join a")
		fmt.Println("       voice call with access logging on to settle this properly.")
	}

	// --- G4 -----------------------------------------------------------------
	finish(r, *jsonOut, *dumpCfg, func() {
		if *access == "" {
			return
		}
		fmt.Println("\n[G4] Domain analysis of " + *access)
		analyseAccessLog(r, *access, cfg)
	})
}

// --- checks -----------------------------------------------------------------

func checkVersionGate(cfg *model.Config) Check {
	x, err := config.Generate(cfg, config.Options{})
	if err != nil {
		return Check{Name: "configuration generates", Pass: false, Detail: err.Error()}
	}
	return Check{Name: "configuration generates", Pass: true,
		Detail: fmt.Sprintf("core version floor %s, profile %s", x.Version.Min, cfg.Profile)}
}

func checkConflicts(cfg *model.Config) Check {
	c := config.Conflicts(cfg)
	if len(c) == 0 {
		return Check{Name: "no conflicting domains", Pass: true, Detail: "each domain resolves to one routing bucket"}
	}
	// Not fatal, but the user believes both rules apply and only one does.
	return Check{Name: "no conflicting domains", Pass: false,
		Detail: strings.Join(c, "; ") + " — tunnel wins by ordering; the other rule is inert"}
}

func checkSharedPool(cfg *model.Config) Check {
	x, err := config.Generate(cfg, config.Options{})
	if err != nil {
		return Check{Name: "fake pool shared with tunnel", Pass: false, Detail: err.Error()}
	}
	toml, err := config.ZeptunTOML(cfg, config.ZeptunOptions{})
	if err != nil {
		return Check{Name: "fake pool shared with tunnel", Pass: false, Detail: err.Error()}
	}
	if !strings.Contains(toml, cfg.FakednsPool) {
		return Check{Name: "fake pool shared with tunnel", Pass: false,
			Detail: "the tunnel include list does not carry " + cfg.FakednsPool +
				"; selected traffic would leave by the physical NIC while claiming to be tunnelled"}
	}
	_ = x
	return Check{Name: "fake pool shared with tunnel", Pass: true,
		Detail: "core fakedns and tunnel include both use " + cfg.FakednsPool}
}

func checkKeepAlive(cfg *model.Config) Check {
	x, err := config.Generate(cfg, config.Options{})
	if err != nil {
		return Check{Name: "keepalive present", Pass: false, Detail: err.Error()}
	}
	so := x.Inbounds[0].Stream.Sockopt
	if so == nil || so.TCPKeepAliveInterval == nil || so.TCPKeepAliveIdle == nil {
		return Check{Name: "keepalive present", Pass: false,
			Detail: "inbound keepalive is missing; the gateway WebSocket will drop when the NAT idles"}
	}
	return Check{Name: "keepalive present", Pass: true,
		Detail: fmt.Sprintf("interval %ds idle %ds", *so.TCPKeepAliveInterval, *so.TCPKeepAliveIdle)}
}

func probeTunnel(r *Report, aetherAddr string, direct health.Result, timeout time.Duration) {
	ua := health.ProbeUDPAssociate(aetherAddr, timeout)
	r.UDPAssociate = &ua
	if ua.Supported {
		fmt.Printf("    yes — the tunnel accepts UDP (relay %s)\n", ua.RelayAddr)
		r.Checks = append(r.Checks, Check{Name: "tunnel carries UDP", Pass: true,
			Detail: "UDP ASSOCIATE accepted; voice can be routed through the tunnel"})
	} else {
		fmt.Printf("    no — %v\n", ua.Err)
		fmt.Println("    -> voice cannot be carried by the tunnel. If voice also fails directly,")
		fmt.Println("       it cannot be fixed by configuration.")
		r.Checks = append(r.Checks, Check{Name: "tunnel carries UDP", Pass: false, Detail: ua.Err.Error()})
	}

	fmt.Println("\n[G3] Exit address through the tunnel")
	tun := health.Probe(context.Background(), aetherAddr, timeout)
	r.Tunnel = &tun
	fmt.Printf("    %s\n", tun)
	if tun.Reachable && direct.Reachable {
		same := tun.IsLocalExit(direct)
		r.TunnelPreservesRealIP = &same
		if same {
			fmt.Println("    -> matches the direct address")
		} else {
			fmt.Printf("    -> differs from the direct address (%s vs %s, country %s)\n",
				tun.ExitIP, direct.ExitIP, orDash(tun.ExitISO))
			fmt.Println("    -> services that refuse Iranian addresses will fail on this route.")
		}
	}
}

func analyseAccessLog(r *Report, path string, cfg *model.Config) {
	b, err := os.ReadFile(path)
	if err != nil {
		fmt.Printf("    could not read log: %v\n", err)
		return
	}
	rep := discovery.Analyse(strings.Split(string(b), "\n"))
	r.LogAnalysis = &LogAnalysis{
		Path:        path,
		Entries:     len(rep.Entries),
		Unparsed:    rep.Unparsed,
		Covered:     rep.Covered(),
		DirectHosts: rep.DirectHosts(),
		Blocked:     rep.Blocked(),
	}
	fmt.Printf("    parsed %d entries (%d unrecognised)\n", len(rep.Entries), rep.Unparsed)
	fmt.Printf("    covered by a rule: %d domains\n", len(rep.Covered()))
	directHosts := rep.DirectHosts()
	if len(directHosts) == 0 {
		fmt.Println("    no domain reached a direct outbound; every destination was claimed by a rule.")
	} else {
		fmt.Printf("    %d domains reached a direct outbound:\n", len(directHosts))
		for _, h := range directHosts {
			fmt.Printf("      %-45s %d conns\n", h, rep.Domains[h]["tcp-direct"]+rep.Domains[h]["udp-direct"])
		}
		// Only domains that look like part of a covered service are worth
		// suggesting. Everything else went direct because the user asked it to.
		fmt.Println("    Suggested suffixes (verify each before adding):")
		for _, s := range discovery.Suffixes(directHosts) {
			fmt.Printf("      %s\n", s)
		}
	}
	if len(rep.Blocked()) > 0 {
		fmt.Println("\n    Blocked domains (a rule matched and then denied — a different problem):")
		for _, h := range rep.Blocked() {
			fmt.Printf("      %s\n", h)
		}
	}
}

// --- reporting --------------------------------------------------------------

type Check struct {
	Name   string `json:"name"`
	Pass   bool   `json:"pass"`
	Detail string `json:"detail"`
}

type LogAnalysis struct {
	Path        string   `json:"path"`
	Entries     int      `json:"entries"`
	Unparsed    int      `json:"unparsed"`
	Covered     []string `json:"covered"`
	DirectHosts []string `json:"directHosts"`
	Blocked     []string `json:"blocked"`
}

type Report struct {
	Version    string    `json:"version"`
	StartedAt  time.Time `json:"startedAt"`
	Host       string    `json:"host"`
	ConfigPath string    `json:"configPath"`
	Profile    string    `json:"profile"`

	Checks []Check `json:"checks"`

	Direct *health.Result          `json:"direct"`
	Frag   *health.Result          `json:"frag"`
	Tunnel *health.Result          `json:"tunnel"`
	UDP    *health.UDPEgressResult `json:"udpEgress"`

	UDPAssociate          *health.UDPAssociateResult `json:"udpAssociate"`
	FragPreservesRealIP   *bool                      `json:"fragPreservesRealIp"`
	TunnelPreservesRealIP *bool                      `json:"tunnelPreservesRealIp"`

	LogAnalysis *LogAnalysis `json:"logAnalysis,omitempty"`

	GeneratedConfig string `json:"generatedConfig,omitempty"`
}

func (r *Report) HasFailure() bool {
	for _, c := range r.Checks {
		if !c.Pass {
			return true
		}
	}
	return false
}

func printHeader(r *Report, cfg *model.Config) {
	h, _ := os.Hostname()
	r.Host = h
	fmt.Println("ARClient selftest")
	fmt.Println("==================")
	fmt.Printf("version      %s\n", r.Version)
	fmt.Printf("host         %s\n", h)
	fmt.Printf("config       %s\n", r.ConfigPath)
	fmt.Printf("profile      %s (%s)\n", cfg.Profile, cfg.Profiles[cfg.Profile].Name)
	fmt.Printf("frag domains %d rules, fakedns %s, mixed on %d\n", len(cfg.Rules), cfg.FakednsPool, cfg.MixedPort)
	fmt.Println()
}

func finish(r *Report, jsonPath string, dumpCfg bool, extra func()) {
	if extra != nil {
		extra()
	}
	fmt.Println("\n[checks]")
	failed := 0
	for _, c := range r.Checks {
		mark := "ok  "
		if !c.Pass {
			mark = "FAIL"
			failed++
		}
		fmt.Printf("  [%s] %-28s %s\n", mark, c.Name, c.Detail)
	}
	if failed > 0 {
		fmt.Printf("\n%d check(s) failed. Network results below may be meaningless.\n", failed)
	}
	if jsonPath != "" {
		b, err := json.MarshalIndent(r, "", "  ")
		if err == nil {
			if err := os.WriteFile(jsonPath, append(b, '\n'), 0o600); err == nil {
				fmt.Printf("\nreport written to %s\n", jsonPath)
			}
		}
	}
	if failed == 0 {
		fmt.Println("\nAll configuration checks passed.")
	}
}

func drainLogs(a *engine.Aether, max int) {
	for i := 0; i < max; i++ {
		select {
		case line := <-a.LogLines():
			fmt.Println("      | " + line)
		case <-time.After(200 * time.Millisecond):
			return
		}
	}
}

func hasTunnelRules(cfg *model.Config) bool {
	for _, r := range cfg.Rules {
		if r.Enabled && r.EffectiveMode() == model.ModeTunnel {
			return true
		}
	}
	return false
}

func assetDir(st *store.Store) string {
	// Geo assets are optional, so the directory may legitimately not exist.
	// The core only fails if a config references geo data that is missing, and
	// the generator only does that when WithGeo is set.
	return filepath.Join(st.Dir(), "geo")
}

func binaryDir(st *store.Store) string {
	if exe, err := os.Executable(); err == nil {
		return filepath.Dir(exe)
	}
	return st.Dir()
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func itoa(n int) string { return fmt.Sprintf("%d", n) }

func fatal(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "selftest: "+format+"\n", a...)
	os.Exit(1)
}
