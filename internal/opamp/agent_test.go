package opamp

import (
	"context"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agardnerIT/falco-opamp/internal/falco"
)

// TestFalcoBinAvailable reports whether the repo can drive a real falco in
// tests (set FALCO_BIN=/path/to/falco).
func TestFalcoBinAvailable(t *testing.T) {
	if _, err := exec.LookPath("falco"); err != nil {
		t.Skip("falco binary not on PATH; integration tests need FALCO_BIN")
	}
}

func TestValidateRulesWithFakeFalco(t *testing.T) {
	dir := t.TempDir()
	rules := filepath.Join(dir, "rules.yaml")
	if err := os.WriteFile(rules, []byte("- rule: ok\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "falco.yaml")
	if err := os.WriteFile(cfg, []byte("rules_files:\n  - "+rules+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(cfg, rules)
	if err != nil {
		t.Fatal(err)
	}
	// a fake falco that accepts whatever it is given
	bin := filepath.Join(dir, "falco.sh")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	a := NewAgent(nil, store, bin, nil)
	if err := a.validateRules(context.Background(), []byte("- rule: x\n")); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

func TestValidateRulesReportsFalcoError(t *testing.T) {
	dir := t.TempDir()
	rules := filepath.Join(dir, "rules.yaml")
	if err := os.WriteFile(rules, []byte("- rule: ok\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "falco.yaml")
	if err := os.WriteFile(cfg, []byte("rules_files:\n  - "+rules+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(cfg, rules)
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "falco.sh")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\necho 'Undefined macro' >&2\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	a := NewAgent(nil, store, bin, nil)
	err = a.validateRules(context.Background(), []byte("- rule: bad\n"))
	if err == nil || !strings.Contains(err.Error(), "Undefined macro") {
		t.Fatalf("expected falco's error text, got %v", err)
	}
}

// TestAgentWithoutOpAMPClient ensures health refresh is a no-op before Start.
func TestRefreshHealthWithoutClient(t *testing.T) {
	// minimal falco fake for the health path
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		//nolint:errcheck
		w.Write([]byte(`{"status":"ok"}`))
	})
	mux.HandleFunc("/reload", func(w http.ResponseWriter, r *http.Request) {
		//nolint:errcheck
		w.Write([]byte(`{"instance_id":"i1","started_generation":1,"applied_generation":1,"rejected_generation":0,"ready":true}`))
	})
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })

	a := NewAgent(falco.New("http://"+l.Addr().String(), ""), nil, "", nil)
	a.RefreshHealth(context.Background()) // must not panic without a client
}
