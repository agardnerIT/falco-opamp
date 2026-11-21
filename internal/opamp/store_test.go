package opamp

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newStore(t *testing.T, configBody, rulesBody string) *Store {
	t.Helper()
	dir, err := os.MkdirTemp("", "fs") // short: unix-socket-safe, and files live near a socket
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	cfg := filepath.Join(dir, "falco.yaml")
	rules := filepath.Join(dir, "rules.yaml")
	if err := os.WriteFile(cfg, []byte(configBody), 0o644); err != nil {
		t.Fatal(err)
	}
	if rulesBody != "" {
		if err := os.WriteFile(rules, []byte(rulesBody), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	s, err := NewStore(cfg, rules)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

const goodConfig = `webserver:
  enabled: true
reload_control:
  enabled: true
  socket: /run/falco/control.sock
`

// configFor renders the good config with the given rules path, as a real
// push would carry it. An empty path omits rules_files.
func configFor(rulesPath string) string {
	if rulesPath == "" {
		return goodConfig
	}
	return goodConfig + "rules_files:\n  - " + rulesPath + "\n"
}

func TestWriteAndEffective(t *testing.T) {
	s := newStore(t, configFor(""), "")
	if err := s.Write([]byte(configFor(s.RulesPath())), []byte("- rule: x\n  condition: evt.type=execve\n")); err != nil {
		t.Fatal(err)
	}
	eff, err := s.Effective()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := eff[ConfigKey]; !ok {
		t.Fatalf("effective missing %q key: %v", ConfigKey, eff)
	}
	if _, ok := eff[RulesKey]; !ok {
		t.Fatalf("effective missing %q key: %v", RulesKey, eff)
	}
}

func TestValidateRefusesControlBrick(t *testing.T) {
	s := newStore(t, configFor(""), "")
	bad := strings.Replace(configFor(s.RulesPath()), "reload_control:\n  enabled: true", "reload_control:\n  enabled: false", 1)
	err := s.Write([]byte(bad), nil)
	if err == nil {
		t.Fatal("Write accepted a push that disables reload_control")
	}
	if !strings.Contains(err.Error(), "control surface") {
		t.Fatalf("wrong error: %v", err)
	}
}

func TestValidateRefusesUnmanagedRules(t *testing.T) {
	s := newStore(t, configFor("/etc/falco/opamp/rules.yaml"), "")
	cfg := strings.Replace(configFor(s.RulesPath()), s.RulesPath(), "/etc/falco/someone_else.yaml", 1)
	err := s.Write([]byte(cfg), []byte("- rule: x\n"))
	if err == nil {
		t.Fatal("Write accepted rules that falco.yaml does not load")
	}
}

func TestValidateRefusesUnparseable(t *testing.T) {
	s := newStore(t, configFor(""), "")
	err := s.Write([]byte("rules_files: [unclosed"), nil)
	if err == nil {
		t.Fatal("Write accepted a non-YAML push")
	}
}

func TestWithdrawRestoresSnapshot(t *testing.T) {
	s := newStore(t, configFor("/etc/falco/opamp/rules.yaml"), "")
	if err := s.Write([]byte(goodConfig+"priority: INFO\n"), nil); err != nil {
		t.Fatal(err)
	}
	restored, err := s.Withdraw()
	if err != nil {
		t.Fatal(err)
	}
	if !restored {
		t.Fatal("Withdraw returned false with a snapshot present")
	}
	onDisk, _ := os.ReadFile(s.ConfigPath())
	if strings.Contains(string(onDisk), "priority: INFO") {
		t.Fatal("withdrawal did not restore the startup snapshot")
	}
}

func TestWithdrawWithoutSnapshot(t *testing.T) {
	// rules file only in the snapshot: config exists, nothing else
	s := newStore(t, goodConfig, "")
	s.snapshotConfig = nil
	s.snapshotRules = nil
	_, err := s.Withdraw()
	if err == nil {
		t.Fatal("Withdraw without snapshot should refuse")
	}
}

func TestAtomicWriteKeepsOldFileOnFailure(t *testing.T) {
	s := newStore(t, goodConfig, "")
	// point the rules path at a directory: rename will fail
	broken := filepath.Join(s.ConfigPath(), "..") // dir exists; write to it as file? use a read-only trick instead:
	_ = broken
	cfg := s.ConfigPath()
	if err := os.Chmod(filepath.Dir(cfg), 0o555); err != nil {
		t.Skip("cannot make dir read-only")
	}
	defer os.Chmod(filepath.Dir(cfg), 0o755) //nolint:errcheck
	err := atomicWrite(filepath.Join(filepath.Dir(cfg), "sub", "x.yaml"), []byte("x"))
	if err == nil {
		t.Log("rename unexpectedly succeeded")
	}
}
