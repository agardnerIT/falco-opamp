package opamp

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/agardnerIT/falco-opamp/internal/falco"
	"github.com/google/uuid"
	"github.com/open-telemetry/opamp-go/client"
	"github.com/open-telemetry/opamp-go/client/types"
	"github.com/open-telemetry/opamp-go/protobufs"
)

// Agent is one sidecar process: an OpAMP client that manages one Falco.
type Agent struct {
	client     client.OpAMPClient
	falco      *falco.Client
	store      *Store
	instanceID string // the falco reload-control process id, reported as an attribute

	validateCmd  string // falco binary for --validate, empty to skip
	reloadPoll   time.Duration
	reloadMaxAge time.Duration
}

// Logger is the minimal logging surface main.go provides.
type Logger interface {
	Printf(format string, v ...any)
}

func NewAgent(falcoClient *falco.Client, store *Store, validateCmd string, log Logger) *Agent {
	return &Agent{
		falco:        falcoClient,
		store:        store,
		validateCmd:  validateCmd,
		reloadPoll:   500 * time.Millisecond,
		reloadMaxAge: 30 * time.Second,
	}
}

// Start builds the OpAMP client and connects. instanceID is used for the
// falco.instance_id attribute so a server can distinguish reload generations
// from reconnects.
func (a *Agent) Start(ctx context.Context, endpoint string, headers map[string]string, instanceID string, heartbeat time.Duration) error {
	a.instanceID = instanceID
	log := stderrLogger{}

	if strings.HasPrefix(endpoint, "ws") {
		// ws(s):// lets the server push without waiting for a poll.
		a.client = client.NewWebSocket(stderrLogger{})
	} else {
		// http(s):// polls; works against any OpAMP server.
		a.client = client.NewHTTP(stderrLogger{})
	}

	desc, err := a.describe(ctx)
	if err != nil {
		// not fatal: connect anyway, describe with what we have
		desc = &protobufs.AgentDescription{
			IdentifyingAttributes: []*protobufs.KeyValue{
				{Key: "service.name", Value: &protobufs.AnyValue{Value: &protobufs.AnyValue_StringValue{StringValue: "falco"}}},
			},
		}
	}

	settings := types.StartSettings{
		OpAMPServerURL: endpoint,
		Header:         toHTTPHeaders(headers),
		InstanceUid:    types.InstanceUid(uuidFrom(instanceID)),
		Callbacks: types.Callbacks{
			OnConnect: func(ctx context.Context) {
				log.Printf("connected to %s", endpoint)
			},
			OnConnectFailed: func(ctx context.Context, err error) {
				log.Printf("connect failed: %v", err)
			},
			OnMessage: a.onMessage,
		},
		RemoteConfigStatus: &protobufs.RemoteConfigStatus{}, // forces the server to re-offer config
		Capabilities: protobufs.AgentCapabilities_AgentCapabilities_AcceptsRemoteConfig |
			protobufs.AgentCapabilities_AgentCapabilities_ReportsRemoteConfig |
			protobufs.AgentCapabilities_AgentCapabilities_ReportsHealth |
			protobufs.AgentCapabilities_AgentCapabilities_ReportsEffectiveConfig,
	}
	if heartbeat > 0 {
		settings.HeartbeatInterval = &heartbeat
	}

	if err := a.client.SetAgentDescription(desc); err != nil {
		return err
	}
	if err := a.client.SetHealth(a.falcoHealth(ctx)); err != nil {
		return err
	}
	return a.client.Start(ctx, settings)
}

func (a *Agent) Stop(ctx context.Context) error {
	if a.client == nil {
		return nil
	}
	return a.client.Stop(ctx)
}

// describe composes the AgentDescription from Falco's own /versions endpoint
// plus the process identity of the reload-control surface.
func (a *Agent) describe(ctx context.Context) (*protobufs.AgentDescription, error) {
	ident := []*protobufs.KeyValue{
		{Key: "service.name", Value: &protobufs.AnyValue{Value: &protobufs.AnyValue_StringValue{StringValue: "falco"}}},
	}
	nonIdent := []*protobufs.KeyValue{
		{Key: "falco.instance_id", Value: &protobufs.AnyValue{Value: &protobufs.AnyValue_StringValue{StringValue: a.instanceID}}},
	}
	if v, err := a.falco.Versions(ctx); err == nil {
		nonIdent = append(nonIdent,
			&protobufs.KeyValue{Key: "falco.version", Value: &protobufs.AnyValue{Value: &protobufs.AnyValue_StringValue{StringValue: v.FalcoVersion}}},
			&protobufs.KeyValue{Key: "falco.libs_version", Value: &protobufs.AnyValue{Value: &protobufs.AnyValue_StringValue{StringValue: v.LibsVersion}}},
			&protobufs.KeyValue{Key: "falco.plugins", Value: &protobufs.AnyValue{Value: &protobufs.AnyValue_StringValue{StringValue: joinKeys(keysOf(v.PluginVersions))}}},
		)
	}
	if host, _ := os.Hostname(); host != "" {
		nonIdent = append(nonIdent,
			&protobufs.KeyValue{Key: "falco.host", Value: &protobufs.AnyValue{Value: &protobufs.AnyValue_StringValue{StringValue: host}}})
	}
	return &protobufs.AgentDescription{
		IdentifyingAttributes:    ident,
		NonIdentifyingAttributes: nonIdent,
	}, nil
}

// onMessage handles the one message type the sidecar accepts: RemoteConfig.
// Everything else (connection settings, packages, commands) is refused by
// leaving the capability unset and the handler absent.
func (a *Agent) onMessage(ctx context.Context, msg *types.MessageData) {
	if msg.RemoteConfig == nil {
		return
	}
	status := a.applyRemoteConfig(ctx, msg.RemoteConfig)
	status.LastRemoteConfigHash = msg.RemoteConfig.GetConfigHash()
	if err := a.client.SetRemoteConfigStatus(status); err != nil {
		a.logError("report status: %v", err)
	}
	if status.Status == protobufs.RemoteConfigStatuses_RemoteConfigStatuses_APPLIED {
		if err := a.client.UpdateEffectiveConfig(ctx); err != nil {
			a.logError("report effective config: %v", err)
		}
	}
}

// applyRemoteConfig runs the whole cycle: parse -> guard -> write -> reload ->
// poll -> verdict. It returns the RemoteConfigStatus to report.
func (a *Agent) applyRemoteConfig(ctx context.Context, remote *protobufs.AgentRemoteConfig) *protobufs.RemoteConfigStatus {
	cfg := remote.Config
	if cfg == nil || len(cfg.ConfigMap) == 0 {
		// Withdrawal: the spec has no delete message; an empty config_map is
		// the contract for "go back to what was here before us".
		restored, err := a.store.Withdraw()
		if err != nil {
			return a.fail(err)
		}
		if !restored {
			return a.fail(fmt.Errorf("withdrawal requested but the sidecar has no startup snapshot"))
		}
		if out := a.reloadAndVerify(ctx); out != falco.Applied {
			return a.fail(fmt.Errorf("withdrawal reload did not apply (outcome %v); falco keeps running its previous config", out))
		}
		return applied()
	}

	configBody, hasConfig := bodyOf(cfg, ConfigKey)
	rulesBody, hasRules := bodyOf(cfg, RulesKey)
	if !hasConfig && !hasRules {
		return a.fail(fmt.Errorf("config_map must contain %q and/or %q; got keys: %s", ConfigKey, RulesKey, joinKeys(mapKeySet(cfg))))
	}
	if err := a.store.Write(configBody, rulesBody); err != nil {
		return a.fail(err)
	}
	if a.validateCmd != "" && rulesBody != nil {
		if err := a.validateRules(ctx, rulesBody); err != nil {
			return a.fail(err)
		}
	}
	if out := a.reloadAndVerify(ctx); out != falco.Applied {
		if out == falco.Rejected {
			// Falco validated and refused; the previous config still runs.
			// The human-readable reason is in falco's own logs, not in
			// GET /reload (generations only).
			return a.fail(fmt.Errorf("falco rejected the pushed config (it keeps running the previous one); the load error is in falco's log output"))
		}
		return a.fail(fmt.Errorf("reload outcome unknown (falco restarted or the deadline passed); check falco's logs before retrying"))
	}
	return applied()
}

// reloadAndVerify POSTs the reload and polls GET /reload for a verdict.
func (a *Agent) reloadAndVerify(ctx context.Context) falco.ApplyOutcome {
	baseline, err := a.falco.Reload(ctx)
	if err != nil {
		a.logError("reload: %v", err)
		return falco.Unknown
	}
	return a.falco.Apply(ctx, baseline, a.reloadPoll, a.reloadMaxAge)
}

// validateRules runs `falco --validate` on the pushed rules when a falco
// binary is available, so a load error surfaces as FAILED before the reload
// (the osquery-opamp pre-compilation pattern).
func (a *Agent) validateRules(ctx context.Context, rules []byte) error {
	// --validate wants a rules file path; write next to the managed file.
	tmp := a.store.RulesPath() + ".opamp-validate"
	if err := os.WriteFile(tmp, rules, 0o600); err != nil {
		return err
	}
	defer os.Remove(tmp) //nolint:errcheck
	out, err := exec.CommandContext(ctx, a.validateCmd, "--validate", tmp).CombinedOutput()
	if err != nil {
		return fmt.Errorf("falco --validate refused the rules: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func (a *Agent) fail(err error) *protobufs.RemoteConfigStatus {
	a.logError("%v", err)
	return &protobufs.RemoteConfigStatus{
		Status:       protobufs.RemoteConfigStatuses_RemoteConfigStatuses_FAILED,
		ErrorMessage: err.Error(),
	}
}

func applied() *protobufs.RemoteConfigStatus {
	return &protobufs.RemoteConfigStatus{
		Status: protobufs.RemoteConfigStatuses_RemoteConfigStatuses_APPLIED,
	}
}

// falcoHealth is the ComponentHealth the sidecar reports: healthy when the
// daemon answers /healthz, with the reload surface's live state as attributes.
func (a *Agent) falcoHealth(ctx context.Context) *protobufs.ComponentHealth {
	h := &protobufs.ComponentHealth{}
	if _, err := a.falco.Healthz(ctx); err != nil {
		h.Healthy = false
		h.LastError = err.Error()
		return h
	}
	h.Healthy = true
	st, err := a.falco.ReloadStatus(ctx)
	if err != nil {
		h.LastError = err.Error()
		return h
	}
	h.Attributes = []*protobufs.KeyValue{
		{Key: "falco.instance_id", Value: strValue(st.InstanceID)},
		{Key: "falco.ready", Value: boolValue(st.Ready)},
		{Key: "falco.applied_generation", Value: intValue(st.AppliedGeneration)},
		{Key: "falco.rejected_generation", Value: intValue(st.RejectedGeneration)},
		{Key: "falco.started_generation", Value: intValue(st.StartedGeneration)},
	}
	if st.RejectedGeneration > st.AppliedGeneration {
		h.Healthy = false
		h.LastError = "last reload was rejected; falco keeps the previous config (see falco logs for the load error)"
	}
	return h
}

// RefreshHealth is called from main's ticker.
func (a *Agent) RefreshHealth(ctx context.Context) {
	if a.client != nil {
		if err := a.client.SetHealth(a.falcoHealth(ctx)); err != nil {
			a.logError("health: %v", err)
		}
	}
}

func (a *Agent) logError(format string, v ...any) {
	fmt.Fprintf(os.Stderr, "falco-opamp: "+format+"\n", v...)
}

func bodyOf(cm *protobufs.AgentConfigMap, key string) ([]byte, bool) {
	obj, ok := cm.ConfigMap[key]
	if !ok || obj == nil {
		return nil, false
	}
	return obj.Body, true
}

func mapKeySet(cm *protobufs.AgentConfigMap) []string {
	out := make([]string, 0, len(cm.ConfigMap))
	for k := range cm.ConfigMap {
		out = append(out, k)
	}
	return out
}

func joinKeys(keys []string) string { return strings.Join(keys, ", ") }

func keysOf(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func strValue(s string) *protobufs.AnyValue {
	return &protobufs.AnyValue{Value: &protobufs.AnyValue_StringValue{StringValue: s}}
}
func boolValue(b bool) *protobufs.AnyValue {
	return &protobufs.AnyValue{Value: &protobufs.AnyValue_BoolValue{BoolValue: b}}
}
func intValue(i int64) *protobufs.AnyValue {
	return &protobufs.AnyValue{Value: &protobufs.AnyValue_IntValue{IntValue: i}}
}

func toHTTPHeaders(headers map[string]string) map[string][]string {
	out := make(map[string][]string, len(headers))
	for k, v := range headers {
		out[k] = []string{v}
	}
	return out
}

// uuidFrom converts the instance id string into the opamp-go type.
func uuidFrom(s string) types.InstanceUid {
	u, err := uuid.Parse(s)
	if err != nil {
		u = uuid.New()
	}
	return types.InstanceUid(u)
}

// stderrLogger satisfies types.Logger.
type stderrLogger struct{}

func (stderrLogger) Printf(format string, v ...any) {
	fmt.Fprintf(os.Stderr, "falco-opamp: "+format+"\n", v...)
}
func (stderrLogger) Debugf(ctx context.Context, format string, v ...any) {}
func (stderrLogger) Errorf(ctx context.Context, format string, v ...any) {
	fmt.Fprintf(os.Stderr, "falco-opamp opamp: "+format+"\n", v...)
}
