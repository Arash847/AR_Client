// Package engine supervises the processes and the in-process core that actually
// carry traffic.
//
// The core runs in-process rather than as a child process. That buys two things
// worth the extra code: a config change is a reconfigure rather than a
// process restart, and the supervisor can see a core crash as a return value
// instead of having to infer it from a port that stopped answering.
package engine

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	// Registers every inbound, outbound and transport, including the
	// finalmask fragment and noise layers. Without this the core starts and
	// then fails to resolve "fragment" and "socks" by name at config load.
	_ "github.com/xtls/xray-core/main/distro/all"

	xcore "github.com/xtls/xray-core/core"

	"arclient/internal/config"
	"arclient/internal/model"
)

// ErrNotRunning is returned when an operation needs a live core and there is
// none.
var ErrNotRunning = errors.New("engine: core is not running")

// Xray is the embedded core.
type Xray struct {
	mu       sync.Mutex
	instance *xcore.Instance
	cfg      *model.Config
	running  bool

	// generated is the exact document the running core was started from. The
	// selftest dumps it, because "the config looks right" and "the core loaded
	// that config" are different claims and only one of them is evidence.
	generated []byte

	// addr is the mixed listener's address, recorded explicitly so a raw
	// config can be probed too. A raw config has no model behind it to derive
	// the port from, and an empty address here would silently make every
	// readiness check fail rather than say why.
	addr string
}

// New returns a core that has not been started.
func New() *Xray { return &Xray{} }

// Running reports whether a live core instance exists.
func (x *Xray) Running() bool {
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.running
}

// GeneratedConfig returns the JSON document the running core was started from.
func (x *Xray) GeneratedConfig() []byte {
	x.mu.Lock()
	defer x.mu.Unlock()
	out := make([]byte, len(x.generated))
	copy(out, x.generated)
	return out
}

// Start builds a core instance from cfg and begins listening.
//
// assetDir, when non-empty, is where geoip.dat and geosite.dat are staged. The
// core refuses to start if a configuration references geo data that is not
// present, and the resulting error does not mention the missing file, so the
// path is set explicitly rather than left to the working directory.
func (x *Xray) Start(cfg *model.Config, opts config.Options, assetDir string) error {
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.running {
		return errors.New("engine: core already running")
	}

	if assetDir != "" {
		if err := os.Setenv("xray.location.asset", assetDir); err != nil {
			return fmt.Errorf("engine: set asset dir: %w", err)
		}
	}

	xcfg, err := config.Generate(cfg, opts)
	if err != nil {
		return fmt.Errorf("engine: %w", err)
	}
	raw, err := json.Marshal(xcfg)
	if err != nil {
		return fmt.Errorf("engine: encode config: %w", err)
	}
	x.cfg = cfg
	return x.startLocked(raw)
}

// startLocked builds and starts an instance from an already-encoded document.
// The caller holds the lock.
func (x *Xray) startLocked(raw []byte) error {
	// core.LoadConfig runs the same loader the core's own command line uses, so
	// a config ARClient generates is validated by exactly the code that will
	// run it, and a field the core does not recognise fails here with a message
	// that names it. That matters more than it sounds: an unrecognised field is
	// otherwise ignored, and "the fragmentation setting was silently dropped"
	// and "the fragmentation setting is not working" are indistinguishable from
	// the outside.
	pb, err := xcore.LoadConfig("json", bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("engine: core rejected the config: %w", err)
	}
	inst, err := xcore.New(pb)
	if err != nil {
		return fmt.Errorf("engine: create core: %w", err)
	}
	if err := inst.Start(); err != nil {
		_ = inst.Close()
		return fmt.Errorf("engine: start core: %w", err)
	}

	x.instance = inst
	x.running = true
	x.generated = raw
	if x.cfg != nil && x.addr == "" {
		x.addr = fmt.Sprintf("%s:%d", config.ListenAddr, x.cfg.MixedPort)
	}
	return nil
}

// StartRaw runs a configuration document verbatim, bypassing the generator.
//
// This exists to A/B a generated configuration against an upstream reference.
// When a route that should work does not, the question is always whether the
// generator or the network is at fault, and the only way to separate them is to
// run the reference through the same core on the same machine. Guessing from the
// generated document is not evidence, because the two can differ in ways that
// only show up as a hang.
func (x *Xray) StartRaw(raw []byte, assetDir string) error {
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.running {
		return errors.New("engine: core already running")
	}
	if len(raw) == 0 {
		return errors.New("engine: empty raw config")
	}
	if assetDir != "" {
		if err := os.Setenv("xray.location.asset", assetDir); err != nil {
			return fmt.Errorf("engine: set asset dir: %w", err)
		}
	}
	// Recover the listener address from the document itself rather than
	// requiring the caller to know the port a reference config happens to use.
	port, err := firstInboundPort(raw)
	if err != nil {
		return err
	}
	x.addr = fmt.Sprintf("%s:%d", config.ListenAddr, port)
	return x.startLocked(raw)
}

// firstInboundPort reports the port of the first inbound listener in a
// configuration document.
func firstInboundPort(raw []byte) (int, error) {
	var probe struct {
		Inbounds []struct {
			Listen string `json:"listen"`
			Port   int    `json:"port"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return 0, fmt.Errorf("engine: read inbound from config: %w", err)
	}
	for _, in := range probe.Inbounds {
		if in.Port > 0 {
			return in.Port, nil
		}
	}
	return 0, errors.New("engine: config has no inbound with a port")
}

// Stop shuts the core down. It is safe to call on a stopped core, because the
// kill switch calls it on every failure path including the ones where startup
// only half succeeded.
func (x *Xray) Stop() error {
	x.mu.Lock()
	defer x.mu.Unlock()
	x.addr = ""
	return x.stopLocked()
}

func (x *Xray) stopLocked() error {
	if !x.running || x.instance == nil {
		x.running = false
		x.instance = nil
		return nil
	}
	err := x.instance.Close()
	x.running = false
	x.instance = nil
	x.cfg = nil
	x.generated = nil
	if err != nil {
		return fmt.Errorf("engine: close core: %w", err)
	}
	return nil
}

// Reconfigure swaps the running configuration.
//
// The core has no supported hot-reload, so this is a stop and a start. Doing it
// that way rather than mutating the live instance is what makes a failed
// reconfigure recoverable: the old instance is already gone, and the next
// Start surfaces the real error instead of leaving a half-updated core that
// routes some flows nowhere.
func (x *Xray) Reconfigure(cfg *model.Config, opts config.Options, assetDir string) error {
	if err := x.Stop(); err != nil {
		return err
	}
	return x.Start(cfg, opts, assetDir)
}

// WaitReady blocks until the mixed listener accepts a connection or the timeout
// expires.
//
// A successful Start means the core object exists, not that anything can reach
// it. Probing the port is the difference between "the app says it is connected"
// and "something answered".
func (x *Xray) WaitReady(addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		if !x.Running() {
			return ErrNotRunning
		}
		c, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			c.Close()
			return nil
		}
		lastErr = err
		time.Sleep(100 * time.Millisecond)
	}
	if lastErr == nil {
		lastErr = errors.New("timed out")
	}
	return fmt.Errorf("engine: %s not accepting connections after %s: %w", addr, timeout, lastErr)
}

// Addr returns the mixed listener's address.
func (x *Xray) Addr() string {
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.addr
}

// WriteGeneratedConfig writes the generated core config to dir for inspection.
//
// Written unconditionally by the selftest. When something is not working, the
// first question is always what the core was actually told, and reconstructing
// that from the rule model is guesswork.
func WriteGeneratedConfig(dir string, raw []byte) (string, error) {
	if len(raw) == 0 {
		return "", errors.New("engine: no generated config to write; core is not running")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("engine: create %s: %w", dir, err)
	}
	path := filepath.Join(dir, "generated-xray.json")
	if err := os.WriteFile(path, append(raw, '\n'), 0o600); err != nil {
		return "", fmt.Errorf("engine: write %s: %w", path, err)
	}
	return path, nil
}
