// falco-opamp is an OpAMP agent for Falco, delivered as an external sidecar.
//
// No changes to Falco's core. The sidecar manages the config files Falco
// loads, and drives Falco's own reload-control API to apply and verify a
// pushed config (Falco 0.45+):
//
//	write files  ->  POST /reload (Unix socket)  ->  poll GET /reload  ->  report APPLIED/FAILED
//
// Contract: the server pushes a config_map with keys "falco.yaml" (the full
// main config) and/or "rules.yaml" (a rules file the sidecar owns). An empty
// config_map withdraws the sidecar's management and restores the config the
// sidecar found on disk at startup.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/agardnerIT/falco-opamp/internal/falco"
	"github.com/agardnerIT/falco-opamp/internal/opamp"
	"github.com/google/uuid"
)

type headerList []string

func (h *headerList) String() string { return strings.Join(*h, "; ") }
func (h *headerList) Set(v string) error {
	*h = append(*h, v)
	return nil
}

func main() {
	var (
		endpoint      = flag.String("endpoint", "", "OpAMP server URL; scheme picks the transport: http(s) polls, ws(s) pushes (required)")
		headers       headerList
		configPath    = flag.String("config", "/etc/falco/falco.yaml", "the main config file this sidecar owns (Falco must already be loading it)")
		rulesPath     = flag.String("rules", "/etc/falco/opamp/rules.yaml", "the managed rules file, referenced by falco.yaml's rules_files")
		controlSocket = flag.String("control-socket", "/run/falco/control.sock", "Falco reload-control Unix socket (reload_control.socket); empty disables reload")
		webserver     = flag.String("webserver", "http://localhost:8765", "base URL of Falco's TCP webserver (healthz/versions/reload observation)")
		stateInterval = flag.Duration("state-interval", 30*time.Second, "how often falco's live state is read and reported as health")
		heartbeat     = flag.Duration("heartbeat", 30*time.Second, "OpAMP heartbeat interval (ws transport)")
		falcoBin      = flag.String("falco-bin", "", "path to a falco binary; pushes are pre-checked with `falco --validate` when set")
		instanceFile  = flag.String("instance-uid-file", "", "file to persist the instance uid across restarts (default: ephemeral)")
		requireRC     = flag.Bool("require-reload-control", true, "refuse pushes that set reload_control.enabled=false; set false when falco is started with -o reload_control.enabled=true (the file may then say false by construction)")
	)
	flag.Var(&headers, "header", "extra HTTP header for the OpAMP server, e.g. --header 'Authorization: Bearer <token>'; repeatable")
	flag.Parse()

	if *endpoint == "" {
		fmt.Fprintln(os.Stderr, "falco-opamp: --endpoint is required")
		flag.Usage()
		os.Exit(2)
	}
	if strings.HasPrefix(*endpoint, "http") == false {
		fmt.Fprintf(os.Stderr, "falco-opamp: --endpoint must be http(s):// or ws(s)://, got %q\n", *endpoint)
		os.Exit(2)
	}
	if *controlSocket == "" && strings.HasPrefix(*webserver, "http") == false {
		fmt.Fprintln(os.Stderr, "falco-opamp: with no control socket, reload observation needs the webserver URL")
		os.Exit(2)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	store, err := opamp.NewStore(*configPath, *rulesPath, *requireRC)
	if err != nil {
		fmt.Fprintf(os.Stderr, "falco-opamp: %v\n", err)
		os.Exit(1)
	}
	if err := store.EnsurePaths(); err != nil {
		fmt.Fprintf(os.Stderr, "falco-opamp: %v\n", err)
		os.Exit(1)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "falco-opamp: %v\n", err)
		os.Exit(1)
	}

	client := falco.New(*webserver, *controlSocket)
	if !client.CanReload(ctx) {
		fmt.Fprintln(os.Stderr, "falco-opamp: cannot POST /reload: is reload_control.enabled=true in falco.yaml, and is the socket dir 0700 and owned by falco's uid?")
		os.Exit(1)
	}
	if *falcoBin != "" {
		if _, err := os.Stat(*falcoBin); err != nil {
			fmt.Fprintf(os.Stderr, "falco-opamp: --falco-bin %s: %v\n", *falcoBin, err)
			os.Exit(1)
		}
	}

	uid := uuid.New()
	if *instanceFile != "" {
		if b, err := os.ReadFile(*instanceFile); err == nil && len(b) == 36 {
			uid = uuid.MustParse(strings.TrimSpace(string(b)))
		}
		if err := os.WriteFile(*instanceFile, []byte(uid.String()), 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "falco-opamp: persist instance uid: %v\n", err)
		}
	}

	agent := opamp.NewAgent(client, store, *falcoBin, stderrPrintf{})
	if err := agent.Start(ctx, *endpoint, parseHeaders(headers), uid.String(), *heartbeat); err != nil {
		fmt.Fprintf(os.Stderr, "falco-opamp: start: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("falco-opamp: connected; config=%s rules=%s socket=%s webserver=%s\n", *configPath, *rulesPath, *controlSocket, *webserver)
	ticker := time.NewTicker(*stateInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			fmt.Println("falco-opamp: shutting down")
			_ = agent.Stop(context.Background())
			return
		case <-ticker.C:
			agent.RefreshHealth(ctx)
		}
	}
}

func parseHeaders(raw []string) map[string]string {
	out := map[string]string{}
	for _, h := range raw {
		k, v, ok := strings.Cut(h, ":")
		if !ok {
			fmt.Fprintf(os.Stderr, "falco-opamp: --header %q is not 'Key: value'\n", h)
			os.Exit(2)
		}
		out[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return out
}

type stderrPrintf struct{}

func (stderrPrintf) Printf(format string, v ...any) {
	fmt.Fprintf(os.Stderr, "falco-opamp: "+format+"\n", v...)
}
