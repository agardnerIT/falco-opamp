# falco-opamp

![Warning: Entirely vibecoded](https://img.shields.io/badge/Warning-Entirely%20vibecoded-orange?style=for-the-badge)
[![Falco supported by opamp-server-py](https://img.shields.io/badge/Falco-supported-blue?logo=falco)](https://github.com/agardnerIT/opamp-server-py)
[![tested against Falco 0.45.2](https://img.shields.io/badge/tested%20against-Falco%200.45.2-green)](https://github.com/falcosecurity/falco/releases/tag/v0.45.2)

An OpAMP agent for Falco, delivered as an **external sidecar**.

No changes to Falco's core. The sidecar owns the config files Falco loads, and
drives Falco's own reload-control API (0.45+) to apply and verify what the
OpAMP server pushes:

| OpAMP need | Falco mechanism |
| --- | --- |
| deliver remote config | write the owned `falco.yaml` + managed rules file, then `POST /reload` (Unix socket) |
| apply feedback | poll `GET /reload`: `applied_generation` past the baseline → `APPLIED`; a newer `rejected_generation` → `FAILED` |
| safe failure | Falco itself validates and keeps the previous config running on rejection |
| report what is running | `GET /healthz`, `GET /versions`, `GET /reload` readiness + generations |
| effective config | the files as written (Falco has no config read-back; this is stated, not claimed) |

Not implemented, and not advertised in the capability bitmask:

- `RESTART`: Falco has no restart RPC; the command is refused
- packages (`PackageService`): rules/plugins come from the config, not OpAMP
  packages — a `falcoctl` integration is the upstream conversation
- `own_metrics`/`own_traces`/`own_logs`, connection settings offers

## Quick start

Prereqs (once, in falco.yaml — the file the sidecar will own):

```yaml
webserver:
  enabled: true            # TCP :8765 — healthz/versions/reload observation
reload_control:
  enabled: true            # Linux; the Unix socket that accepts POST /reload
  socket: /run/falco/control.sock
```

The socket directory must already exist, be dedicated to the listener, and be
owned by Falco's effective UID with mode `0700` (this is Falco's own
validation — a wrong-mode dir refuses to start). In Kubernetes, share a
dedicated emptyDir with the sidecar only.

Then run the sidecar next to Falco:

```bash
go install github.com/agardnerIT/falco-opamp@latest
falco-opamp \
  --endpoint http://opamp.example.com:4320/v1/opamp \
  --header 'Authorization: Bearer <token>' \
  --config /etc/falco/falco.yaml \
  --rules /etc/falco/opamp/rules.yaml \
  --control-socket /run/falco/control.sock \
  --webserver http://localhost:8765
```

Point `--endpoint` at any OpAMP server; the scheme picks the transport
(`http(s)://` polls, `ws(s)://` lets the server push without waiting for a
poll). Add `--falco-bin /usr/bin/falco` to pre-check pushed rules with
`falco --validate` before a reload.

## The push contract

The server pushes a `config_map` with these keys (content type
`application/yaml`):

- **`falco.yaml`** — the complete main config, written to `--config`
- **`rules.yaml`** — the managed rules file, written to `--rules`; must be
  referenced by `rules_files` in the pushed `falco.yaml`

Guards (a violating push is reported `FAILED`, never applied):

- `reload_control.enabled` must stay `true` — a push that removes the
  sidecar's own control surface would brick the fleet
- without a control socket, `webserver.enabled` must stay `true`
- `rules_files` must include the managed rules path

**Withdrawal:** an empty `config_map` is the OpAMP "delete" signal. The
sidecar restores the config it found on disk at startup and reloads — it
never writes an empty file, because a `falco.yaml` is mandatory.

## Applied vs. working

An `APPLIED` status means Falco validated and applied the config — the same
caveat as everywhere: rule semantics can only be judged by running Falco.
Failures carry a coarse reason only: `GET /reload` reports generations, and
the human-readable load error is in Falco's own logs. The sidecar says so
rather than inventing detail.

`watch_config_files` should be `false` when the sidecar manages the files:
Falco's own file watcher reloads on every write, racing the POST/GET
protocol and double-incrementing generations.

## Status

**Working end to end.** Verified live against a real `falcosecurity/falco`
0.45.2 container and [opamp-server-py](https://github.com/agardnerIT/opamp-server-py),
which carries the matching `falco` profile: the agent registers as `falco`
(not `generic`), a server push lands as `falco.yaml` + `rules.yaml`, the reload
control API applies it (`applied_generation` advances, `ready=true`), and the
agent reports `APPLIED` back — the whole propose → apply → confirm round trip.
Rejected configs are verified live too: Falco keeps the previous config running
and the sidecar reports `FAILED` honestly.

| OpAMP server support | |
|---|---|
| [opamp-server-py](https://github.com/agardnerIT/opamp-server-py) | ✅ profile included, push verified live |
| Any standard-OpAMP server | ✅ protocol-level; config keys are this sidecar's contract |

Known wrinkles (logged, not fixed): the `CanReload` startup probe triggers one
harmless real reload; the server UI shows the raw enum string
(`RemoteConfigStatuses_APPLIED`) for remote config status; snapshot persistence
across sidecar restarts is memory-only.

Not yet: end-to-end tests against a live OpAMP server in CI, the `falcoctl`
package-management phase.

## Requirements

- Falco 0.45.0+ with `reload_control` (Linux; observation-only elsewhere)
- Go 1.23+
- `github.com/open-telemetry/opamp-go` (the official OpAMP client)
- A persistent uid: pass `--instance-uid-file` so a sidecar restart reconnects
  as the **same agent** — without it every restart registers a new agent until
  the server's stale-agent reaper removes the ghost

## Development

```bash
go test ./... -timeout 60s
```

## Layout

```
main.go                       flags, wiring, lifecycle
internal/falco/client.go      Falco's webserver + reload-control client (the wire contract lives here)
internal/opamp/store.go       file ownership, snapshot/withdrawal, push guards
internal/opamp/agent.go       OpAMP client wiring, apply cycle, health
```

Apache-2.0
