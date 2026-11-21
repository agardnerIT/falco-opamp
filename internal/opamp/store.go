package opamp

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// The config_map keys this sidecar understands.
const (
	ConfigKey  = "falco.yaml" // the full main config; written to --config
	RulesKey   = "rules.yaml" // the managed rules file; written to --rules
	FormatType = "application/yaml"
)

// Store owns the files the sidecar manages. Exactly as osquery-opamp owns a
// config source: the sidecar never edits Falco's other files, and it reports
// what it wrote (Falco has no config read-back endpoint).
type Store struct {
	configPath string // the main config file the sidecar owns, e.g. /etc/falco/falco.yaml
	rulesPath  string // the managed rules file, referenced by `rules_files` in the config

	// requireReloadControl refuses pushes that set reload_control.enabled
	// false. It is false for deployments where Falco was started with
	// `-o reload_control.enabled=true`: the file then disagrees with the
	// running process by construction, and enforcing the file would refuse
	// every push. The operator asserts the process override with a flag.
	requireReloadControl bool

	snapshotConfig []byte // on-disk content at startup; the withdrawal target
	snapshotRules  []byte
}

func NewStore(configPath, rulesPath string, requireReloadControl bool) (*Store, error) {
	s := &Store{configPath: configPath, rulesPath: rulesPath, requireReloadControl: requireReloadControl}
	s.snapshotConfig, _ = os.ReadFile(configPath) // missing is fine: nothing to restore
	s.snapshotRules, _ = os.ReadFile(rulesPath)
	if s.snapshotConfig == nil {
		return nil, fmt.Errorf("main config %s does not exist: create it (Falco must already be loading it) before starting the sidecar", configPath)
	}
	return s, nil
}

// ConfigPath / RulesPath are the ownership contract, reported to the server
// in the effective config.
func (s *Store) ConfigPath() string { return s.configPath }
func (s *Store) RulesPath() string  { return s.rulesPath }

// ErrBrickControl is returned when a push would remove the sidecar's own
// control surface from the config it is writing.
var ErrBrickControl = errors.New("push would disable the sidecar's own control surface")

// validate checks a pushed main config against the rules of the contract:
// it must parse, must keep reload_control enabled (and the webserver up when
// there is no control socket), and must load the managed rules file.
func (s *Store) validate(configBody []byte, rules bool) error {
	var doc map[string]any
	if err := yaml.Unmarshal(configBody, &doc); err != nil {
		return fmt.Errorf("falco.yaml does not parse as YAML: %w", err)
	}
	if s.requireReloadControl {
		if enabled, err := boolSetting(doc, "reload_control", "enabled"); err != nil || !enabled {
			return fmt.Errorf("%w: reload_control.enabled must be true in the pushed falco.yaml", ErrBrickControl)
		}
	}
	if enabled, _ := boolSetting(doc, "webserver", "enabled"); !enabled && s.needsWebserver() {
		return fmt.Errorf("%w: webserver.enabled must be true when no control socket is configured", ErrBrickControl)
	}
	if rules {
		files, _ := doc["rules_files"].([]any)
		found := false
		for _, f := range files {
			if p, ok := f.(string); ok && p == s.rulesPath {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("pushed rules file %s is not loaded: falco.yaml's rules_files must include %s", RulesKey, s.rulesPath)
		}
	}
	return nil
}

// needsWebserver reports whether GET /reload observation depends on the TCP
// webserver (no control socket configured).
func (s *Store) needsWebserver() bool { return false }

// Write applies one push: replace the owned files, returning the files that
// changed. configBody may be nil (rules-only push) and vice versa.
func (s *Store) Write(configBody, rulesBody []byte) error {
	if configBody != nil {
		if err := s.validate(configBody, rulesBody != nil); err != nil {
			return err
		}
	}
	if configBody != nil {
		if err := atomicWrite(s.configPath, configBody); err != nil {
			return fmt.Errorf("write %s: %w", s.configPath, err)
		}
	}
	if rulesBody != nil {
		if err := atomicWrite(s.rulesPath, rulesBody); err != nil {
			return fmt.Errorf("write %s: %w", s.rulesPath, err)
		}
	}
	return nil
}

// Withdraw restores the on-disk state the sidecar found at startup: the spec
// has no "delete config" message, and a falco.yaml is mandatory (rules,
// outputs), so the withdrawal answer is the startup snapshot, not an empty
// file. Returns (true, nil) when a snapshot existed and was restored.
func (s *Store) Withdraw() (bool, error) {
	if s.snapshotConfig == nil && s.snapshotRules == nil {
		return false, errors.New("nothing to withdraw: the sidecar found no config on disk at startup")
	}
	if s.snapshotConfig != nil {
		if err := atomicWrite(s.configPath, s.snapshotConfig); err != nil {
			return false, fmt.Errorf("restore %s: %w", s.configPath, err)
		}
	}
	if s.snapshotRules != nil {
		if err := atomicWrite(s.rulesPath, s.snapshotRules); err != nil {
			return false, fmt.Errorf("restore %s: %w", s.rulesPath, err)
		}
	}
	return true, nil
}

// Effective returns the files as currently written, for the
// AgentEffectiveConfig report. Falco has no config read-back, so this is the
// sidecar's honest "what we handed Falco".
func (s *Store) Effective() (map[string][]byte, error) {
	cfg, err := os.ReadFile(s.configPath)
	if err != nil {
		return nil, err
	}
	out := map[string][]byte{ConfigKey: cfg}
	if rules, err := os.ReadFile(s.rulesPath); err == nil && len(rules) > 0 {
		out[RulesKey] = rules
	}
	return out, nil
}

func boolSetting(doc map[string]any, section, key string) (bool, error) {
	sec, ok := doc[section].(map[string]any)
	if !ok {
		return false, fmt.Errorf("section %q missing", section)
	}
	b, _ := sec[key].(bool)
	return b, nil
}

// atomicWrite replaces a file in one rename, so a concurrent Falco file
// watcher never reads a half-written document.
func atomicWrite(path string, body []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".opamp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) //nolint:errcheck -- no-op after a successful rename
	if _, err := tmp.Write(body); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
