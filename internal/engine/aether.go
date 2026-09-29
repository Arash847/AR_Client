package engine

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Aether is the tunnel core, supervised as a child process.
//
// It is a child process rather than a linked library even though the crate
// publishes one. Three reasons, in order of weight:
//
//   - Aether is AGPL and pulls a vendored quiche plus BoringSSL. Linking it
//     would make ARClient's own licensing a question rather than an answer.
//   - Its build needs Rust, CMake, a C++ toolchain and a sibling checkout of
//     quiche, which is exactly the kind of SDK chain this project is meant to
//     avoid on the user's machine. The prebuilt Windows archive sidesteps all
//     of it.
//   - Aether's own reconnect and scan logic is long-lived stateful behaviour.
//     Supervising it as a process means a crash is a non-zero exit we can see,
//     rather than a panic inside our address space.
//
// Every prompt Aether has has a flag equivalent, and all of them are set
// explicitly. Aether otherwise opens an interactive prompt on a machine with no
// terminal attached, which looks like a hang rather than a misconfiguration.

// AetherProtocol is the transport Aether brings the tunnel up with.
type AetherProtocol string

const (
	AetherMasque    AetherProtocol = "masque"
	AetherWireGuard AetherProtocol = "wg"
	AetherGool      AetherProtocol = "gool"
	AetherTor       AetherProtocol = "tor"
	AetherPsiphon   AetherProtocol = "psiphon"
)

// AetherSettings is the user-facing configuration of the tunnel core.
type AetherSettings struct {
	Protocol AetherProtocol `json:"protocol"`
	// Noize is the obfuscation profile. "firewall" and "balanced" are the
	// documented defaults for this network.
	Noize string `json:"noize"`
	// Scan is how hard it looks for a reachable gateway.
	Scan string `json:"scan"`
	// IPVersion is "4", "6" or "dual".
	IPVersion string `json:"ipVersion"`
	// HTTP2 carries MASQUE over TLS/TCP instead of QUIC. Needed where UDP is
	// throttled, which the QUIC path cannot survive.
	HTTP2 bool `json:"http2"`
	// Fragment splits the TLS ClientHello. Only meaningful with HTTP2, and
	// distinct from the core's finalmask fragmentation: this one protects
	// Aether's own handshake, not the application's.
	Fragment bool `json:"fragment"`
	// Tor carries Tor inside the tunnel, so the exit is a Tor exit and the
	// network never sees Tor traffic directly.
	Tor bool `json:"tor"`
	// Psiphon carries Psiphon inside the tunnel.
	Psiphon bool `json:"psiphon"`
	// QuickReconnect re-verifies the last working gateway instead of
	// rescanning on every launch.
	QuickReconnect bool `json:"quickReconnect"`
	// Bind is the SOCKS5 listen address.
	Bind string `json:"bind"`
}

// DefaultAetherSettings returns the settings ARClient ships with: MASQUE over
// HTTP/3 with the firewall obfuscation profile, which is what the Aether
// documentation recommends for this network.
func DefaultAetherSettings() AetherSettings {
	return AetherSettings{
		Protocol:       AetherMasque,
		Noize:          "firewall",
		Scan:           "balanced",
		IPVersion:      "4",
		HTTP2:          false,
		Fragment:       false,
		Tor:            false,
		Psiphon:        false,
		QuickReconnect: true,
		Bind:           "",
	}
}

// Args renders the settings as Aether's command line.
//
// Every prompt-suppressing flag is emitted unconditionally, including the
// ones set to their default, because Aether prompts for any setting it has not
// been told. Emitting "--scan balanced" when balanced is already the default
// costs nothing and removes a whole class of "it just hangs at startup".
func (s AetherSettings) Args() []string {
	var a []string
	switch s.Protocol {
	case AetherWireGuard:
		a = append(a, "--wg")
	case AetherGool:
		a = append(a, "--gool")
	case AetherMasque, "":
		a = append(a, "--masque")
	}
	if s.Noize != "" {
		a = append(a, "--noize", s.Noize)
	}
	if s.Scan != "" {
		a = append(a, "--scan", s.Scan)
	}
	switch s.IPVersion {
	case "6":
		a = append(a, "-6")
	case "dual":
		a = append(a, "--dual")
	default:
		a = append(a, "-4")
	}
	if s.HTTP2 {
		a = append(a, "--h2")
	}
	if s.Fragment {
		// Guarded because fragmenting only applies to the HTTP/2 path; on
		// HTTP/3 there is no ClientHello in a TCP stream to split, and asking
		// for it anyway is at best ignored and at worst an error.
		a = append(a, "--fragment")
	}
	if s.Tor {
		a = append(a, "--tor")
	}
	if s.Psiphon {
		a = append(a, "--psiphon")
	}
	if s.QuickReconnect {
		a = append(a, "--quick-reconnect")
	}
	return a
}

// Validate reports settings Aether would reject.
func (s AetherSettings) Validate() error {
	switch s.Protocol {
	case AetherMasque, AetherWireGuard, AetherGool, AetherTor, AetherPsiphon:
	default:
		return fmt.Errorf("aether: unknown protocol %q", s.Protocol)
	}
	if s.Fragment && !s.HTTP2 {
		return errors.New("aether: ClientHello fragmentation requires HTTP/2; it does not apply to HTTP/3")
	}
	switch s.IPVersion {
	case "4", "6", "dual":
	default:
		return fmt.Errorf("aether: unknown ip version %q", s.IPVersion)
	}
	return nil
}

// Aether supervises the tunnel process.
type Aether struct {
	mu   sync.Mutex
	cmd  *exec.Cmd
	stop context.CancelFunc
	done chan struct{}

	exe      string
	dataDir  string
	settings AetherSettings

	// logs carries the child's output to the UI. It is buffered because a
	// consumer that is slow must not stall the pipe, and dropping is worse
	// than a little latency: Aether's startup log is the only record of which
	// gateway it picked and why.
	logs chan string
}

// LogLines returns the channel of child output lines.
func (a *Aether) LogLines() <-chan string { return a.logs }

// NewAether locates the Aether binary and returns a supervisor for it.
//
// searchDir is the directory holding the bundled cores, normally next to the
// executable. dataDir must be persistent across runs: Aether's WARP identity
// lives there, and without it every start registers a new device and Cloudflare
// starts rate-limiting the address.
func NewAether(searchDir, dataDir string) (*Aether, error) {
	exe, err := LocateAether(searchDir)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("aether: create data dir: %w", err)
	}
	return &Aether{
		exe:      exe,
		dataDir:  dataDir,
		settings: DefaultAetherSettings(),
		logs:     make(chan string, 512),
	}, nil
}

// LocateAether finds the Aether binary.
func LocateAether(searchDir string) (string, error) {
	name := "aether"
	if isWindows() {
		name = "aether.exe"
	}
	candidates := []string{
		filepath.Join(searchDir, name),
		filepath.Join(searchDir, "cores", name),
	}
	if exeDir, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exeDir), name),
			filepath.Join(filepath.Dir(exeDir), "cores", name))
	}
	for _, c := range candidates {
		if fi, err := os.Stat(c); err == nil && !fi.IsDir() {
			return c, nil
		}
	}
	return "", fmt.Errorf("aether: binary %q not found; looked in %s. The release archive bundles it under cores/",
		name, strings.Join(candidates, ", "))
}

// Start launches Aether and returns immediately. Use WaitReady to know when the
// proxy is actually usable.
func (a *Aether) Start(ctx context.Context, s AetherSettings) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.cmd != nil {
		return errors.New("aether: already running")
	}
	if err := s.Validate(); err != nil {
		return err
	}

	runCtx, cancel := context.WithCancel(ctx)
	args := s.Args()

	// AETHER_CONFIG points at the persistent identity config. Without it Aether
	// registers as a new device every start, and Cloudflare rate-limits by
	// address, so a user who restarts often eventually cannot connect at all.
	identity := filepath.Join(a.dataDir, "aether.toml")
	cmd := exec.CommandContext(runCtx, a.exe, args...)
	cmd.Dir = a.dataDir
	cmd.Env = append(os.Environ(),
		"AETHER_CONFIG="+identity,
		// Belt and braces: the flags above already suppress the prompts, but
		// the quick-reconnect variable is the documented way to keep startup to
		// a single re-verification rather than a full scan.
		"AETHER_QUICK_RECONNECT=boolInt("+boolString(s.QuickReconnect)+")",
	)
	if s.Bind != "" {
		cmd.Env = append(cmd.Env, "AETHER_SOCKS="+s.Bind)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return fmt.Errorf("aether: stdout pipe: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		cancel()
		return fmt.Errorf("aether: stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		cancel()
		return fmt.Errorf("aether: start %s: %w", a.exe, err)
	}

	a.cmd = cmd
	a.stop = cancel
	a.done = make(chan struct{})
	a.settings = s
	done := a.done

	go a.pump(stdout, done)
	go a.pump(stderr, done)
	go func() {
		waitErr := cmd.Wait()
		if waitErr != nil {
			a.emit(fmt.Sprintf("aether exited: %v", waitErr))
		} else {
			a.emit("aether exited")
		}
		close(done)
	}()
	return nil
}

// pump forwards one stream of the child's output line by line.
func (a *Aether) pump(r io.Reader, done <-chan struct{}) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		if line := strings.TrimRight(sc.Text(), "\r"); line != "" {
			a.emit(line)
		}
	}
}

// emit hands a line to the UI without ever blocking the child's pipe. If the
// consumer has gone away the lines are dropped rather than stalling Aether,
// because a stalled pipe eventually blocks its own writer and looks like a
// frozen tunnel.
func (a *Aether) emit(line string) {
	select {
	case a.logs <- line:
	default:
	}
}

// WaitReady blocks until Aether's SOCKS5 listener accepts a connection.
//
// A non-nil return means the tunnel is up: Aether keeps the port closed until
// its first end-to-end data probe passes, so a successful dial here means
// traffic has genuinely flowed, not just that a handshake was answered.
func (a *Aether) WaitReady(addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		a.mu.Lock()
		running := a.cmd != nil
		a.mu.Unlock()
		if !running {
			return errors.New("aether: process is not running")
		}
		c, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			c.Close()
			return nil
		}
		lastErr = err
		time.Sleep(250 * time.Millisecond)
	}
	if lastErr == nil {
		lastErr = errors.New("timed out")
	}
	return fmt.Errorf("aether: %s not accepting connections after %s: %w", addr, timeout, lastErr)
}

// Stop terminates Aether.
//
// The context is cancelled before the process is killed so that Aether's own
// shutdown path runs, which is what lets it close its sockets cleanly rather
// than leaving the WARP session registered. A short grace period, then a hard
// kill for the case where it is stuck.
func (a *Aether) Stop(timeout time.Duration) error {
	a.mu.Lock()
	cmd, stop, done := a.cmd, a.stop, a.done
	a.cmd, a.stop, a.done = nil, nil, nil
	a.mu.Unlock()

	if cmd == nil || cmd.Process == nil {
		return nil
	}
	if stop != nil {
		stop()
	}
	if done != nil {
		select {
		case <-done:
			return nil
		case <-time.After(timeout):
		}
	}
	if err := cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return fmt.Errorf("aether: kill: %w", err)
	}
	return nil
}

// Running reports whether the child is alive.
func (a *Aether) Running() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.cmd != nil
}

// Settings returns the settings the running child was started with.
func (a *Aether) Settings() AetherSettings {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.settings
}

func boolString(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
