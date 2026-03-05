# TUI + VyOS Container — Design Document

**Date:** 2026-03-05
**Status:** Approved

---

## Overview

Add a Textual-based TUI for managing the service, replace systemd with a Python supervisor daemon for container mode, package as a Docker image for VyOS container subsystem, and publish via GitHub Actions to ghcr.io.

---

## New Files

```
src/
  tui.py               # Textual TUI app
  daemon.py            # Python supervisor (container PID 1)
Dockerfile
.github/
  workflows/
    docker.yml         # Build + push to ghcr.io on push/tag
```

---

## Part 1: TUI (`src/tui.py`)

### Framework

**Textual** — modern Python TUI framework. Added as pip dependency in Dockerfile.

### Screens

#### Screen 1 — Dashboard (default)

```
┌─ remnawave-sync ─────────────────────────────────────────────┐
│  [F1 Status]  [F2 Nodes]  [F3 Config]                        │
├──────────────────────────────────────────────────────────────┤
│  ● sing-box   RUNNING     Current: NL-1 (nl1.example.com)    │
│  ● sync       OK 5m ago   Protocol: VLESS+Reality            │
│  ● heartbeat  OK 30s ago  Fails: 0/2                         │
├──────────────────────────────────────────────────────────────┤
│  [S] Force Sync    [R] Restart sing-box    [Q] Quit          │
└──────────────────────────────────────────────────────────────┘
```

Data sources:
- sing-box status → read `state.json` + check process via `pgrep sing-box` or systemctl/docker
- Current node → `state_manager.get_current_node()`
- Fail count → `state_manager.get_fail_count()`
- Last sync/heartbeat → parse last line of `sync.log` / `heartbeat.log`

#### Screen 2 — Nodes

```
┌─ Nodes (3) ──────────────────────────────────────────────────┐
│  ► [1] ✓ NL-1   nl1.example.com:443   VLESS+Reality         │
│    [2]   DE-1   de1.example.com:443   VLESS+Reality         │
│    [3]   TR-1   tr.example.com:443    Trojan+TLS            │
│                                                              │
│  [Enter] Switch to selected    [↑↓] Navigate                │
└──────────────────────────────────────────────────────────────┘
```

Switching a node:
1. `state_manager.set_current_index(selected)`
2. Regenerate config via `config_generator.generate_config()`
3. Reload sing-box (via daemon API or systemctl)

#### Screen 3 — Config / Sub-link

```
┌─ Configuration ──────────────────────────────────────────────┐
│  Subscription URL:                                           │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ https://panel.example.com/sub/TOKEN                  │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                              │
│  Sync interval:        [10min  ]                             │
│  Heartbeat interval:   [30s    ]                             │
│  Fail threshold:       [2      ]                             │
│  Direct IP (geoip):    [private,ru                    ]      │
│  Direct site (geosite):[ru                            ]      │
│                                                              │
│  [Save & Sync]   [Cancel]                                   │
└──────────────────────────────────────────────────────────────┘
```

"Save & Sync":
1. Write updated values back to `config.env`
2. Run `sync.py` subprocess (triggers re-fetch + restart if changed)

### Usage

```bash
# On bare VyOS (systemd mode):
python3 /usr/local/lib/remnawave/tui.py

# Inside container:
docker exec -it remnawave python3 /app/src/tui.py
```

---

## Part 2: Container Daemon (`src/daemon.py`)

Replaces systemd when running inside a Docker container.

### Responsibilities

- PID 1 in container
- Downloads sing-box + geo files on first start (calls `binary_manager`)
- Reads `config.env`, runs initial sync
- Starts sing-box as subprocess
- Runs sync loop in background thread (every `SYNC_INTERVAL`)
- Runs heartbeat loop in background thread (every `HEARTBEAT_INTERVAL`)
- Handles SIGTERM / SIGINT for graceful shutdown

### Thread model

```
daemon.py (main thread)
  ├── subprocess: sing-box run -c /etc/sing-box/config.json
  ├── Thread: sync_loop()      — sleep(interval) → sync.main()
  └── Thread: heartbeat_loop() — sleep(interval) → heartbeat.main()
```

### Restart logic

If sing-box subprocess exits unexpectedly → restart with 5s backoff (max 3 retries, then exit).

---

## Part 3: Dockerfile

```dockerfile
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip iproute2 ca-certificates curl \
    && pip3 install --no-cache-dir textual \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY src/ /app/src/
COPY config.env.example /app/

ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["python3", "/app/src/daemon.py"]
```

### Required VyOS container capabilities

- `cap-add net-admin` — for TUN device creation
- Device: `/dev/net/tun` → `/dev/net/tun`
- Volumes: `/config/remnawave:/etc/remnawave`, `/config/sing-box:/etc/sing-box`

### VyOS config snippet

```
set container name remnawave image 'ghcr.io/OWNER/remnawave-sync:latest'
set container name remnawave cap-add 'net-admin'
set container name remnawave device tun source '/dev/net/tun' destination '/dev/net/tun'
set container name remnawave volume config source '/config/remnawave' destination '/etc/remnawave'
set container name remnawave volume singbox source '/config/sing-box' destination '/etc/sing-box'
set container name remnawave volume logs source '/config/remnawave/logs' destination '/var/log/remnawave'
```

---

## Part 4: GitHub Actions (`.github/workflows/docker.yml`)

### Triggers

- Push to `main` → build + tag as `latest`
- Push tag `v*` → build + tag as `vX.Y.Z` + `latest`

### Matrix

- Platforms: `linux/amd64`, `linux/arm64`

### Steps

1. Checkout
2. Set up QEMU (for arm64 cross-build)
3. Set up Docker Buildx
4. Login to `ghcr.io` with `GITHUB_TOKEN`
5. Extract metadata (tags, labels)
6. Build & push multi-arch image

### Image naming

```
ghcr.io/OWNER/remnawave-sync:latest
ghcr.io/OWNER/remnawave-sync:v1.0.0
```

---

## Error Handling

| Scenario | Behavior |
|---|---|
| sing-box crash | daemon.py restarts it (up to 3 times) |
| Subscription fetch fail | use cached nodes.json |
| TUI can't reach state files | show "N/A", no crash |
| Config save fails (permissions) | show error in TUI status bar |
