// Package netcfg controls the operating system's proxy settings.
//
// This is the capture layer: it is what actually routes an application's traffic
// into the core. Without it the core listens on loopback and nothing ever
// connects, which looks exactly like a filtering failure and is not one.
//
// Every change is reversible and the previous state is remembered. That is not
// a convenience: if this process dies while the system proxy points at a
// listener that no longer exists, the machine loses its ability to reach the
// internet through any proxy-aware application, and the user has to know where
// to look. Restoring on the way out, and on the way in, is what keeps a crash
// from becoming an outage.
package netcfg

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows/registry"
)

// Proxy state under HKCU\Software\Microsoft\Windows\CurrentVersion\Internet
// Settings. This is the location Chromium and Electron read on Windows, which is
// what makes Discord pick the setting up without being told to.
const (
	settingsKey = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`
	// proxyOverride keeps loopback and local addresses off the proxy. Without
	// it, a request to the local network would be sent to us and then dialled
	// back out, which fails for anything not reachable from us.
	proxyOverride = "<local>"
)

// State is the proxy configuration as it was found, so it can be put back
// exactly. Restoring a remembered value rather than "off" matters when the user
// already had a proxy configured.
type State struct {
	// Present is false when the key did not exist, so a restore removes the
	// values rather than writing empty ones.
	Present     bool
	ProxyEnable uint32
	ProxyServer string
	Override    string
	AutoConfig  string
}

// Read returns the current system proxy settings.
func Read() (State, error) {
	k, err := registry.OpenKey(registry.CURRENT_USER, settingsKey, registry.QUERY_VALUE)
	if err != nil {
		if err == registry.ErrNotExist {
			// No key means no proxy has ever been configured here.
			return State{}, nil
		}
		return State{}, fmt.Errorf("netcfg: open settings: %w", err)
	}
	defer k.Close()

	s := State{Present: true}
	if v, _, err := k.GetIntegerValue("ProxyEnable"); err == nil {
		s.ProxyEnable = uint32(v)
	}
	if v, _, err := k.GetStringValue("ProxyServer"); err == nil {
		s.ProxyServer = v
	}
	if v, _, err := k.GetStringValue("ProxyOverride"); err == nil {
		s.Override = v
	}
	if v, _, err := k.GetStringValue("AutoConfigURL"); err == nil {
		s.AutoConfig = v
	}
	return s, nil
}

// Set points the system proxy at addr, for example "127.0.0.1:10808".
//
// The listener must accept HTTP as well as SOCKS: the core's mixed inbound does,
// which is why a single address serves Chromium, Electron and curl.
func Set(addr string) error {
	if !strings.Contains(addr, ":") {
		return fmt.Errorf("netcfg: %q is not host:port", addr)
	}
	k, _, err := registry.CreateKey(registry.CURRENT_USER, settingsKey, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("netcfg: open settings for write: %w", err)
	}
	defer k.Close()

	for _, kv := range []struct {
		name  string
		value any
	}{
		{"ProxyEnable", uint32(1)},
		{"ProxyServer", addr},
		{"ProxyOverride", proxyOverride},
		// A leftover auto-configuration URL would take precedence over the
		// explicit proxy and silently win, so it is cleared while we are active.
		{"AutoConfigURL", ""},
	} {
		var werr error
		switch v := kv.value.(type) {
		case uint32:
			werr = k.SetDWordValue(kv.name, v)
		case string:
			werr = k.SetStringValue(kv.name, v)
		}
		if werr != nil {
			return fmt.Errorf("netcfg: set %s: %w", kv.name, werr)
		}
	}
	return notify()
}

// Restore puts a previously read state back.
//
// Clearing values that were absent is preferred over writing them as empty,
// because an empty ProxyServer is not the same as no ProxyServer to some
// readers, and the difference shows up as a proxy that appears configured but
// is not.
func Restore(s State) error {
	k, _, err := registry.CreateKey(registry.CURRENT_USER, settingsKey, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("netcfg: open settings for write: %w", err)
	}
	defer k.Close()

	if !s.Present {
		for _, name := range []string{"ProxyEnable", "ProxyServer", "ProxyOverride", "AutoConfigURL"} {
			if err := k.DeleteValue(name); err != nil && err != registry.ErrNotExist {
				return fmt.Errorf("netcfg: delete %s: %w", name, err)
			}
		}
		return notify()
	}
	for _, kv := range []struct {
		name string
		val  any
	}{
		{"ProxyEnable", s.ProxyEnable},
		{"ProxyServer", s.ProxyServer},
		{"ProxyOverride", s.Override},
		{"AutoConfigURL", s.AutoConfig},
	} {
		var werr error
		switch v := kv.val.(type) {
		case uint32:
			werr = k.SetDWordValue(kv.name, v)
		case string:
			werr = k.SetStringValue(kv.name, v)
		}
		if werr != nil {
			return fmt.Errorf("netcfg: restore %s: %w", kv.name, werr)
		}
	}
	return notify()
}

// Clear turns the proxy off, for the panic path where restoring the previous
// value is itself the wrong thing to do.
func Clear() error {
	return Restore(State{Present: true, ProxyEnable: 0})
}

// notify tells running applications that the settings changed.
//
// Without this the registry is updated and nothing else: applications that are
// already running keep their cached configuration, so a user who starts the
// client, then opens Discord, would see Discord miss the change entirely and
// conclude the feature does not work. The two options are the documented pair
// for "settings changed" and "re-read them".
func notify() error {
	const (
		optionRefresh         = 37
		optionSettingsChanged = 39
	)
	wininet := syscall.NewLazyDLL("wininet.dll")
	proc := wininet.NewProc("InternetSetOptionW")
	for _, opt := range []uintptr{optionSettingsChanged, optionRefresh} {
		if _, _, err := proc.Call(0, opt, 0, 0); err != syscall.Errno(0) {
			// A failure here does not mean the setting was not applied, only
			// that already-running applications were not told. Reporting it
			// would be honest but is not fatal, and the caller has a working
			// configuration either way.
			return fmt.Errorf("netcfg: notify (running apps may need restarting): %w", err)
		}
	}
	return nil
}

// Describe renders a state for logging, so a report says what the proxy was set
// to rather than only that it was changed.
func Describe(s State) string {
	if s.ProxyEnable == 0 || s.ProxyServer == "" {
		return "off"
	}
	return fmt.Sprintf("%s (override %q)", s.ProxyServer, s.Override)
}

// unused keeps the unsafe import honest if the syscall signature changes shape.
var _ = unsafe.Pointer(nil)
