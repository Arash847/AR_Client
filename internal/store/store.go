// Package store persists the application configuration.
//
// Everything lives in one JSON file under the user's config directory. A
// censorship tool should be inspectable and hand-editable: a user whose
// filtering conditions have changed needs to be able to adjust a fragment
// offset without waiting for a release, and a single file they can open in a
// text editor is the difference between doing that and not.
//
// Writes are atomic. A half-written config would be read back as a truncated
// file, and since the file decides how traffic is routed, being unable to start
// is a much worse failure than being unable to save.
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"arclient/internal/model"
)

// FileName is the config file's name inside the store directory.
const FileName = "config.json"

// Store reads and writes the configuration.
type Store struct {
	dir string
	mu  sync.Mutex
}

// DefaultDir returns the per-user directory ARClient keeps its state in.
//
// It also holds Aether's identity, which is the reason it matters: a WARP
// identity that is not persisted makes every start register as a new device,
// and Cloudflare begins rate-limiting the address. Losing this directory is not
// a cosmetic reset.
func DefaultDir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("locate user config dir: %w", err)
	}
	return filepath.Join(base, "ARClient"), nil
}

// Open returns a store rooted at the default directory, creating it if needed.
func Open() (*Store, error) {
	dir, err := DefaultDir()
	if err != nil {
		return nil, err
	}
	return OpenAt(dir)
}

// OpenAt returns a store rooted at dir, creating it if needed.
func OpenAt(dir string) (*Store, error) {
	if dir == "" {
		return nil, errors.New("store: empty directory")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create %s: %w", dir, err)
	}
	return &Store{dir: dir}, nil
}

// Dir returns the store's root directory.
func (s *Store) Dir() string { return s.dir }

// Path returns the configuration file's full path.
func (s *Store) Path() string { return filepath.Join(s.dir, FileName) }

// Load reads the configuration, falling back to defaults when none exists yet.
//
// A corrupt file is reported rather than silently replaced. Overwriting it would
// destroy the user's hand-tuned fragment offsets, which are the one thing in
// this app they cannot regenerate from scratch.
func (s *Store) Load() (*model.Config, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	b, err := os.ReadFile(s.Path())
	if errors.Is(err, os.ErrNotExist) {
		return model.DefaultConfig(), nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", s.Path(), err)
	}

	var cfg model.Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w\n\nThe file has not been modified. Fix or remove it, then restart.\n"+
			"It holds hand-tuned fragmentation values that cannot be regenerated.", s.Path(), err)
	}
	cfg.Normalize()
	return &cfg, nil
}

// Save writes the configuration atomically.
func (s *Store) Save(cfg *model.Config) error {
	if cfg == nil {
		return errors.New("store: nil config")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveLocked(cfg)
}

func (s *Store) saveLocked(cfg *model.Config) error {
	cfg.Normalize()
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("encode config: %w", err)
	}
	b = append(b, '\n')

	// Write beside the target and rename over it, so a crash mid-write leaves
	// the previous file intact rather than a truncated one.
	tmp, err := os.CreateTemp(s.dir, ".config-*.json")
	if err != nil {
		return fmt.Errorf("create temp config: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once the rename succeeds

	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp config: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync temp config: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp config: %w", err)
	}
	// Config can carry hand-tuned offsets; it is not a secret, but keeping it
	// user-only avoids any surprise about who can read someone's routing rules.
	if err := os.Chmod(tmpName, 0o600); err != nil && !errors.Is(err, os.ErrPermission) {
		return fmt.Errorf("chmod temp config: %w", err)
	}
	if err := os.Rename(tmpName, s.Path()); err != nil {
		return fmt.Errorf("replace %s: %w", s.Path(), err)
	}
	return nil
}
