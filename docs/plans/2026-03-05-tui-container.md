# TUI + VyOS Container — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a Textual TUI for managing remnawave-sync, a Python supervisor daemon as container PID 1, a Dockerfile for VyOS container deployment, and a GitHub Actions workflow that publishes multi-arch images to ghcr.io.

**Architecture:** `src/daemon.py` replaces systemd in container mode — manages sing-box subprocess + sync/heartbeat threads with restart logic. `src/tui_helpers.py` provides pure testable helper functions. `src/tui.py` is the Textual app with three screens (Status, Nodes, Config). Dockerfile builds on `debian:bookworm-slim` and installs `textual` via pip.

**Tech Stack:** Python 3.9+, Textual (pip), iproute2 (ip tuntap), Docker Buildx (multi-arch), GitHub Actions (ghcr.io)

---

## Project Structure (additions)

```
src/
  daemon.py          # container PID 1 supervisor
  tui_helpers.py     # pure functions for TUI data (testable)
  tui.py             # Textual TUI app
tests/
  test_daemon.py
  test_tui_helpers.py
Dockerfile
.github/
  workflows/
    docker.yml
```

---

### Task 1: Daemon Supervisor

**Files:**
- Create: `src/daemon.py`
- Create: `tests/test_daemon.py`

**Step 1: Write failing tests**

Create `tests/test_daemon.py`:

```python
import pytest
import threading
import time
from unittest.mock import patch, MagicMock, call
from src.daemon import Daemon, parse_interval


class TestParseInterval:
    def test_minutes(self):
        assert parse_interval("10min") == 600

    def test_seconds(self):
        assert parse_interval("30s") == 30

    def test_bare_number(self):
        assert parse_interval("120") == 120

    def test_whitespace(self):
        assert parse_interval("  5min  ") == 300


class TestDaemon:
    def _make_daemon(self, tmp_path):
        config = tmp_path / "config.env"
        config.write_text(
            "SUBSCRIPTION_URL=https://example.com/sub/TOKEN\n"
            "SYNC_INTERVAL=10min\n"
            "HEARTBEAT_INTERVAL=30s\n"
            "TUN_INTERFACE=tun0\n"
            "TUN_ADDRESS=172.19.0.1/30\n"
            "XRAY_BIN=/usr/local/bin/sing-box\n"
            "XRAY_CONFIG=/etc/sing-box/config.json\n"
        )
        return Daemon(str(config))

    def test_init_loads_config(self, tmp_path):
        d = self._make_daemon(tmp_path)
        assert d.env["SUBSCRIPTION_URL"] == "https://example.com/sub/TOKEN"
        assert d.sync_interval == 600
        assert d.heartbeat_interval == 30

    def test_stop_sets_event(self, tmp_path):
        d = self._make_daemon(tmp_path)
        assert not d._stop.is_set()
        d.stop()
        assert d._stop.is_set()

    def test_setup_tun_calls_ip_commands(self, tmp_path):
        d = self._make_daemon(tmp_path)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            d.setup_tun()
        calls = [str(c) for c in mock_run.call_args_list]
        assert any("tuntap" in c for c in calls)
        assert any("addr" in c for c in calls)
        assert any("link" in c for c in calls)

    def test_sing_box_restart_on_exit(self, tmp_path):
        d = self._make_daemon(tmp_path)
        restart_count = []

        def fake_popen(cmd, **kwargs):
            proc = MagicMock()
            proc.wait.return_value = 1  # non-zero exit
            restart_count.append(1)
            if len(restart_count) >= 2:
                d._stop.set()  # stop after 2 restarts
            return proc

        with patch("subprocess.Popen", side_effect=fake_popen):
            with patch("time.sleep"):
                d._run_sing_box()

        assert len(restart_count) >= 1

    def test_loop_calls_fn_periodically(self, tmp_path):
        d = self._make_daemon(tmp_path)
        calls = []

        def fake_fn(config_path):
            calls.append(1)
            if len(calls) >= 2:
                d._stop.set()

        with patch("time.sleep"):
            d._loop(fake_fn, 1, "test")

        assert len(calls) >= 2
```

**Step 2: Run tests to verify they FAIL**

```bash
cd C:\Users\Honor\Documents\vyos-remnawave && python -m pytest tests/test_daemon.py -v 2>&1 | head -15
```

Expected: `ImportError: cannot import name 'Daemon'`

**Step 3: Implement `src/daemon.py`**

```python
#!/usr/bin/env python3
"""
Container PID 1 supervisor — manages sing-box + sync + heartbeat.

Usage:
  python3 daemon.py [--config /etc/remnawave/config.env]
"""
from __future__ import annotations
import argparse
import logging
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.sync import main as sync_main, load_env
from src.heartbeat import main as heartbeat_main

log = logging.getLogger("remnawave-daemon")

MAX_RESTARTS = 5
RESTART_DELAY = 5  # seconds between sing-box restarts


def parse_interval(s: str) -> int:
    """Parse '10min', '30s', or bare seconds string to int seconds."""
    s = s.strip()
    if s.endswith("min"):
        return int(s[:-3]) * 60
    if s.endswith("s"):
        return int(s[:-1])
    return int(s)


class Daemon:
    def __init__(self, config_path: str):
        self.config_path = config_path
        self.env = load_env(config_path)
        self._stop = threading.Event()
        self._sing_box_proc: subprocess.Popen | None = None
        self._restart_count = 0
        self.sync_interval = parse_interval(self.env.get("SYNC_INTERVAL", "10min"))
        self.heartbeat_interval = parse_interval(self.env.get("HEARTBEAT_INTERVAL", "30s"))

    # ── Public interface ───────────────────────────────────────────────────────

    def start(self) -> None:
        """Run initial sync, set up TUN, start background threads."""
        log.info("Starting remnawave daemon")

        # Initial sync: downloads binaries + generates config
        try:
            sync_main(self.config_path)
        except Exception as exc:
            log.error("Initial sync failed: %s", exc)

        self.setup_tun()

        # sing-box subprocess thread
        threading.Thread(target=self._run_sing_box, daemon=True, name="sing-box").start()

        # Sync loop thread
        threading.Thread(
            target=self._loop, args=(sync_main, self.sync_interval, "sync"),
            daemon=True, name="sync-loop",
        ).start()

        # Heartbeat loop thread
        threading.Thread(
            target=self._loop, args=(heartbeat_main, self.heartbeat_interval, "heartbeat"),
            daemon=True, name="heartbeat-loop",
        ).start()

    def stop(self) -> None:
        """Signal all threads to stop and terminate sing-box."""
        log.info("Stopping daemon")
        self._stop.set()
        if self._sing_box_proc and self._sing_box_proc.poll() is None:
            self._sing_box_proc.terminate()
            try:
                self._sing_box_proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self._sing_box_proc.kill()

    def wait(self) -> None:
        """Block until stop() is called."""
        try:
            while not self._stop.is_set():
                self._stop.wait(timeout=1)
        except KeyboardInterrupt:
            self.stop()

    def setup_tun(self) -> None:
        """Create and bring up the TUN interface."""
        tun_if = self.env.get("TUN_INTERFACE", "tun0")
        tun_addr = self.env.get("TUN_ADDRESS", "172.19.0.1/30")
        cmds = [
            ["/sbin/ip", "tuntap", "add", "mode", "tun", tun_if],
            ["/sbin/ip", "addr", "add", tun_addr, "dev", tun_if],
            ["/sbin/ip", "link", "set", tun_if, "up"],
        ]
        for cmd in cmds:
            result = subprocess.run(cmd, capture_output=True)
            if result.returncode != 0:
                log.debug("ip command %s: %s", cmd[2], result.stderr.decode().strip())

    # ── Internal ──────────────────────────────────────────────────────────────

    def _run_sing_box(self) -> None:
        """Run sing-box, restarting on crash up to MAX_RESTARTS times."""
        sing_box_bin = self.env.get("XRAY_BIN", "/usr/local/bin/sing-box")
        config = self.env.get("XRAY_CONFIG", "/etc/sing-box/config.json")

        while not self._stop.is_set() and self._restart_count < MAX_RESTARTS:
            log.info("Starting sing-box (attempt %d)", self._restart_count + 1)
            self._sing_box_proc = subprocess.Popen([sing_box_bin, "run", "-c", config])
            ret = self._sing_box_proc.wait()
            if self._stop.is_set():
                break
            self._restart_count += 1
            log.warning(
                "sing-box exited (code %d), restart %d/%d in %ds",
                ret, self._restart_count, MAX_RESTARTS, RESTART_DELAY,
            )
            time.sleep(RESTART_DELAY)

        if self._restart_count >= MAX_RESTARTS:
            log.error("sing-box restart limit reached — stopping daemon")
            self._stop.set()

    def _loop(self, fn, interval: int, name: str) -> None:
        """Run fn(config_path) repeatedly, sleeping interval seconds between calls."""
        # First run: wait one interval (initial sync already done in start())
        self._stop.wait(timeout=interval)
        while not self._stop.is_set():
            try:
                fn(self.config_path)
            except Exception as exc:
                log.error("%s loop error: %s", name, exc)
            self._stop.wait(timeout=interval)


def main(config_path: str = "/etc/remnawave/config.env") -> int:
    log_dir = load_env(config_path).get("LOG_DIR", "/var/log/remnawave")
    Path(log_dir).mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[
            logging.FileHandler(f"{log_dir}/daemon.log"),
            logging.StreamHandler(),
        ],
    )

    daemon = Daemon(config_path)

    def _on_signal(sig, _frame):
        log.info("Received signal %d, shutting down", sig)
        daemon.stop()

    signal.signal(signal.SIGTERM, _on_signal)
    signal.signal(signal.SIGINT, _on_signal)

    daemon.start()
    daemon.wait()
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="/etc/remnawave/config.env")
    args = parser.parse_args()
    sys.exit(main(args.config))
```

**Step 4: Run tests**

```bash
cd C:\Users\Honor\Documents\vyos-remnawave && python -m pytest tests/test_daemon.py -v
```

Expected: All tests PASS.

**Step 5: Commit**

```bash
cd C:\Users\Honor\Documents\vyos-remnawave && git add src/daemon.py tests/test_daemon.py && git commit -m "feat: container daemon supervisor"
```

---

### Task 2: TUI Helper Functions

**Files:**
- Create: `src/tui_helpers.py`
- Create: `tests/test_tui_helpers.py`

These are pure functions that the TUI screens call — no Textual dependency, fully testable.

**Step 1: Write failing tests**

Create `tests/test_tui_helpers.py`:

```python
import json
import tempfile
import pytest
from pathlib import Path
from src.tui_helpers import (
    get_status,
    read_config,
    write_config,
    get_last_log_line,
    detect_reload_mode,
)
from src.uri_parser import ParsedNode
from src.state_manager import StateManager


def make_node(name: str, protocol: str = "vless") -> ParsedNode:
    return ParsedNode(
        protocol=protocol, host=f"{name}.example.com", port=443,
        name=name, uuid="uuid", security="reality",
        reality_pbk="KEY", reality_sid="sid",
    )


class TestGetStatus:
    def setup_method(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.nodes_file = self.tmp / "nodes.json"
        self.state_file = self.tmp / "state.json"

    def _make_sm(self, nodes, index=0):
        sm = StateManager(str(self.nodes_file), str(self.state_file))
        sm.save_nodes(nodes)
        sm.set_current_index(index)
        return sm

    def test_current_node_name(self):
        sm = self._make_sm([make_node("NL-1"), make_node("DE-1")], index=0)
        status = get_status(str(self.nodes_file), str(self.state_file))
        assert status["current_node_name"] == "NL-1"

    def test_current_node_index(self):
        sm = self._make_sm([make_node("A"), make_node("B")], index=1)
        status = get_status(str(self.nodes_file), str(self.state_file))
        assert status["current_index"] == 1

    def test_node_count(self):
        self._make_sm([make_node("A"), make_node("B"), make_node("C")])
        status = get_status(str(self.nodes_file), str(self.state_file))
        assert status["node_count"] == 3

    def test_fail_count(self):
        sm = self._make_sm([make_node("A")])
        sm.increment_fail_count()
        sm.increment_fail_count()
        status = get_status(str(self.nodes_file), str(self.state_file))
        assert status["fail_count"] == 2

    def test_no_nodes_returns_defaults(self):
        status = get_status(str(self.nodes_file), str(self.state_file))
        assert status["current_node_name"] == "N/A"
        assert status["node_count"] == 0

    def test_protocol_label(self):
        sm = self._make_sm([make_node("NL-1", protocol="trojan")])
        status = get_status(str(self.nodes_file), str(self.state_file))
        assert status["current_node_protocol"] == "trojan"


class TestReadWriteConfig:
    def setup_method(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.config = self.tmp / "config.env"
        self.config.write_text(
            "SUBSCRIPTION_URL=https://example.com/sub/TOKEN\n"
            "SYNC_INTERVAL=10min\n"
            "GEO_DIRECT_IP=private,ru\n"
            "# comment line\n"
        )

    def test_read_config_returns_dict(self):
        cfg = read_config(str(self.config))
        assert cfg["SUBSCRIPTION_URL"] == "https://example.com/sub/TOKEN"
        assert cfg["SYNC_INTERVAL"] == "10min"
        assert cfg["GEO_DIRECT_IP"] == "private,ru"

    def test_read_config_skips_comments(self):
        cfg = read_config(str(self.config))
        assert "# comment line" not in cfg

    def test_read_config_missing_file_returns_empty(self):
        cfg = read_config("/nonexistent/config.env")
        assert cfg == {}

    def test_write_config_updates_value(self):
        write_config(str(self.config), {"SUBSCRIPTION_URL": "https://new.com/sub/NEW"})
        cfg = read_config(str(self.config))
        assert cfg["SUBSCRIPTION_URL"] == "https://new.com/sub/NEW"

    def test_write_config_preserves_other_keys(self):
        write_config(str(self.config), {"SUBSCRIPTION_URL": "https://new.com/sub/NEW"})
        cfg = read_config(str(self.config))
        assert cfg["SYNC_INTERVAL"] == "10min"

    def test_write_config_adds_new_key(self):
        write_config(str(self.config), {"NEW_KEY": "value"})
        cfg = read_config(str(self.config))
        assert cfg["NEW_KEY"] == "value"


class TestGetLastLogLine:
    def setup_method(self):
        self.tmp = Path(tempfile.mkdtemp())

    def test_returns_last_line(self):
        log = self.tmp / "sync.log"
        log.write_text("line 1\nline 2\nline 3\n")
        assert get_last_log_line(str(log)) == "line 3"

    def test_missing_file_returns_none(self):
        assert get_last_log_line("/nonexistent/sync.log") is None

    def test_empty_file_returns_none(self):
        log = self.tmp / "empty.log"
        log.write_text("")
        assert get_last_log_line(str(log)) is None


class TestDetectReloadMode:
    def test_returns_string(self):
        mode = detect_reload_mode()
        assert mode in ("systemd", "container", "unknown")
```

**Step 2: Run tests to verify they FAIL**

```bash
cd C:\Users\Honor\Documents\vyos-remnawave && python -m pytest tests/test_tui_helpers.py -v 2>&1 | head -15
```

Expected: `ImportError: cannot import name 'get_status'`

**Step 3: Implement `src/tui_helpers.py`**

```python
"""
Pure helper functions for the TUI — no Textual dependency.
These are tested independently from the UI.
"""
from __future__ import annotations
import os
import subprocess
from pathlib import Path
from typing import Any, Dict, Optional

from .state_manager import StateManager


def get_status(nodes_file: str, state_file: str) -> Dict[str, Any]:
    """Return current service status as a plain dict."""
    sm = StateManager(nodes_file, state_file)
    nodes = sm.load_nodes()
    node = sm.get_current_node()
    return {
        "current_node_name": node.name if node else "N/A",
        "current_node_host": node.host if node else "N/A",
        "current_node_port": node.port if node else 0,
        "current_node_protocol": node.protocol if node else "N/A",
        "current_index": sm.get_current_index(),
        "node_count": len(nodes),
        "fail_count": sm.get_fail_count(),
    }


def read_config(config_path: str) -> Dict[str, str]:
    """Read config.env and return key→value dict (skips comments and blanks)."""
    result: Dict[str, str] = {}
    try:
        for line in Path(config_path).read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            result[key.strip()] = value.strip()
    except FileNotFoundError:
        pass
    return result


def write_config(config_path: str, updates: Dict[str, str]) -> None:
    """Update specific keys in config.env, preserving all other lines."""
    path = Path(config_path)
    lines = path.read_text().splitlines(keepends=True) if path.exists() else []

    updated_keys = set()
    new_lines = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("#") or "=" not in stripped:
            new_lines.append(line)
            continue
        key = stripped.split("=", 1)[0].strip()
        if key in updates:
            new_lines.append(f"{key}={updates[key]}\n")
            updated_keys.add(key)
        else:
            new_lines.append(line)

    # Append any new keys not already in file
    for key, value in updates.items():
        if key not in updated_keys:
            new_lines.append(f"{key}={value}\n")

    path.write_text("".join(new_lines))


def get_last_log_line(log_path: str) -> Optional[str]:
    """Return the last non-empty line of a log file, or None if unavailable."""
    try:
        text = Path(log_path).read_text()
        lines = [l for l in text.splitlines() if l.strip()]
        return lines[-1] if lines else None
    except (FileNotFoundError, OSError):
        return None


def detect_reload_mode() -> str:
    """Detect whether we're running under systemd or in a container."""
    # If systemctl is available and works, we're in systemd mode
    if Path("/run/systemd/system").exists():
        return "systemd"
    # If we're inside a Docker container
    if Path("/.dockerenv").exists():
        return "container"
    return "unknown"


def reload_sing_box() -> bool:
    """Reload or restart sing-box. Returns True on success."""
    mode = detect_reload_mode()
    if mode == "systemd":
        result = subprocess.run(
            ["/bin/systemctl", "reload-or-restart", "sing-box"],
            capture_output=True,
        )
        return result.returncode == 0
    # Container mode: SIGHUP to sing-box process
    result = subprocess.run(
        ["/usr/bin/pkill", "-HUP", "sing-box"],
        capture_output=True,
    )
    return result.returncode == 0
```

**Step 4: Run tests**

```bash
cd C:\Users\Honor\Documents\vyos-remnawave && python -m pytest tests/test_tui_helpers.py -v
```

Expected: All tests PASS.

**Step 5: Commit**

```bash
cd C:\Users\Honor\Documents\vyos-remnawave && git add src/tui_helpers.py tests/test_tui_helpers.py && git commit -m "feat: TUI helper functions"
```

---

### Task 3: TUI App

**Files:**
- Create: `src/tui.py`

> No unit tests — Textual UI is verified visually. The helper functions (Task 2) cover all business logic.

**Step 1: Create `src/tui.py`**

```python
#!/usr/bin/env python3
"""
remnawave TUI — manage the proxy service from a terminal.

Usage:
  python3 tui.py [--config /etc/remnawave/config.env]

Requires: pip install textual
"""
from __future__ import annotations
import argparse
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from textual.app import App, ComposeResult
    from textual.binding import Binding
    from textual.containers import Container, Horizontal, Vertical
    from textual.screen import Screen
    from textual.widgets import (
        Button, DataTable, Footer, Header, Input, Label,
        Static, TabbedContent, TabPane,
    )
    from textual.reactive import reactive
except ImportError:
    print("ERROR: textual is not installed. Run: pip install textual")
    sys.exit(1)

from src.tui_helpers import (
    get_status, read_config, write_config,
    get_last_log_line, reload_sing_box,
)
from src.state_manager import StateManager
from src.config_generator import ConfigSettings, generate_config
import json


# ── Status Panel ─────────────────────────────────────────────────────────────

STATUS_CSS = """
.status-row { height: 1; }
.label      { width: 20; color: $text-muted; }
.value      { color: $success; }
.value-warn { color: $warning; }
.value-err  { color: $error; }
"""


class StatusPanel(Static):
    """Shows sing-box status, current node, fail count."""

    DEFAULT_CSS = STATUS_CSS

    def __init__(self, config_path: str, **kwargs):
        super().__init__(**kwargs)
        self.config_path = config_path
        from src.sync import load_env
        env = load_env(config_path)
        self._nodes_file = env.get("NODES_FILE", "/etc/remnawave/nodes.json")
        self._state_file = env.get("STATE_FILE", "/etc/remnawave/state.json")
        self._log_dir = env.get("LOG_DIR", "/var/log/remnawave")

    def compose(self) -> ComposeResult:
        st = get_status(self._nodes_file, self._state_file)
        sync_last = get_last_log_line(f"{self._log_dir}/sync.log") or "—"
        hb_last = get_last_log_line(f"{self._log_dir}/heartbeat.log") or "—"
        fail = st["fail_count"]

        yield Label(f"Current node : {st['current_node_name']}  "
                    f"({st['current_node_host']}:{st['current_node_port']})")
        yield Label(f"Protocol     : {st['current_node_protocol']}")
        yield Label(f"Node index   : {st['current_index'] + 1} / {st['node_count']}")
        yield Label(f"Fail count   : {fail}")
        yield Label(f"Last sync    : {sync_last[-80:]}")
        yield Label(f"Last hb      : {hb_last[-80:]}")


# ── Nodes Screen ──────────────────────────────────────────────────────────────

class NodesScreen(Screen):
    BINDINGS = [
        Binding("enter", "switch_node", "Switch to selected"),
        Binding("escape", "app.pop_screen", "Back"),
    ]

    def __init__(self, config_path: str, **kwargs):
        super().__init__(**kwargs)
        self.config_path = config_path
        from src.sync import load_env
        env = load_env(config_path)
        self._nodes_file = env.get("NODES_FILE", "/etc/remnawave/nodes.json")
        self._state_file = env.get("STATE_FILE", "/etc/remnawave/state.json")
        self._xray_config = env.get("XRAY_CONFIG", "/etc/sing-box/config.json")
        self._sm = StateManager(self._nodes_file, self._state_file)

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        yield DataTable(id="nodes-table")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one(DataTable)
        table.add_columns("#", "Name", "Host", "Port", "Protocol", "Active")
        nodes = self._sm.load_nodes()
        current = self._sm.get_current_index()
        for i, node in enumerate(nodes):
            active = "✓" if i == current else ""
            table.add_row(
                str(i + 1), node.name, node.host, str(node.port),
                node.protocol, active,
                key=str(i),
            )

    def action_switch_node(self) -> None:
        table = self.query_one(DataTable)
        if table.cursor_row is None:
            return
        row_key = table.get_row_at(table.cursor_row)[0]
        idx = int(table.get_row_at(table.cursor_row)[0]) - 1
        self._sm.set_current_index(idx)

        # Regenerate config
        node = self._sm.get_current_node()
        if node:
            from src.sync import load_env
            env = load_env(self.config_path)
            settings = ConfigSettings(
                tun_interface=env.get("TUN_INTERFACE", "tun0"),
                tun_address=env.get("TUN_ADDRESS", "172.19.0.1/30"),
                geo_direct_ip=env.get("GEO_DIRECT_IP", "private,ru").split(","),
                geo_direct_site=env.get("GEO_DIRECT_SITE", "ru").split(","),
                geoip_path=env.get("GEOIP_PATH", "/etc/sing-box/geoip.db"),
                geosite_path=env.get("GEOSITE_PATH", "/etc/sing-box/geosite.db"),
            )
            config = generate_config(node, settings)
            Path(self._xray_config).parent.mkdir(parents=True, exist_ok=True)
            Path(self._xray_config).write_text(json.dumps(config, indent=2))
            reload_sing_box()
            self.notify(f"Switched to {node.name}", severity="information")

        self.app.pop_screen()


# ── Config Screen ─────────────────────────────────────────────────────────────

EDITABLE_KEYS = [
    ("SUBSCRIPTION_URL", "Subscription URL (sub-link)"),
    ("SYNC_INTERVAL", "Sync interval (e.g. 10min)"),
    ("HEARTBEAT_INTERVAL", "Heartbeat interval (e.g. 30s)"),
    ("HEARTBEAT_FAIL_THRESHOLD", "Fail threshold (number)"),
    ("GEO_DIRECT_IP", "Direct GeoIP (e.g. private,ru)"),
    ("GEO_DIRECT_SITE", "Direct GeoSite (e.g. ru)"),
]


class ConfigScreen(Screen):
    BINDINGS = [
        Binding("ctrl+s", "save", "Save & Sync"),
        Binding("escape", "app.pop_screen", "Cancel"),
    ]

    def __init__(self, config_path: str, **kwargs):
        super().__init__(**kwargs)
        self.config_path = config_path

    def compose(self) -> ComposeResult:
        cfg = read_config(self.config_path)
        yield Header(show_clock=False)
        with Vertical():
            for key, label in EDITABLE_KEYS:
                yield Label(label)
                yield Input(value=cfg.get(key, ""), id=f"input-{key}")
            yield Horizontal(
                Button("Save & Sync", variant="success", id="btn-save"),
                Button("Cancel", id="btn-cancel"),
            )
        yield Footer()

    def action_save(self) -> None:
        updates = {}
        for key, _ in EDITABLE_KEYS:
            inp = self.query_one(f"#input-{key}", Input)
            updates[key] = inp.value.strip()
        write_config(self.config_path, updates)
        # Trigger sync in background
        subprocess.Popen([
            sys.executable,
            str(Path(__file__).parent / "sync.py"),
            "--config", self.config_path,
        ])
        self.notify("Config saved. Sync triggered.", severity="information")
        self.app.pop_screen()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-save":
            self.action_save()
        elif event.button.id == "btn-cancel":
            self.app.pop_screen()


# ── Main App ──────────────────────────────────────────────────────────────────

class RemnaApp(App):
    """remnawave-sync TUI."""

    CSS = """
    StatusPanel { height: auto; padding: 1 2; }
    DataTable   { height: 1fr; }
    Button      { margin: 0 1; }
    """

    BINDINGS = [
        Binding("f2", "push_screen('nodes')", "Nodes"),
        Binding("f3", "push_screen('config')", "Config"),
        Binding("s", "force_sync", "Force Sync"),
        Binding("q", "quit", "Quit"),
    ]

    def __init__(self, config_path: str, **kwargs):
        super().__init__(**kwargs)
        self.config_path = config_path

    def compose(self) -> ComposeResult:
        yield Header()
        yield StatusPanel(self.config_path)
        yield Footer()

    def on_mount(self) -> None:
        self.install_screen(NodesScreen(self.config_path), name="nodes")
        self.install_screen(ConfigScreen(self.config_path), name="config")

    def action_force_sync(self) -> None:
        subprocess.Popen([
            sys.executable,
            str(Path(__file__).parent / "sync.py"),
            "--config", self.config_path,
        ])
        self.notify("Sync triggered", severity="information")


def main(config_path: str = "/etc/remnawave/config.env") -> None:
    app = RemnaApp(config_path)
    app.run()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="/etc/remnawave/config.env")
    args = parser.parse_args()
    main(args.config)
```

**Step 2: Verify syntax**

```bash
cd C:\Users\Honor\Documents\vyos-remnawave && python -c "import ast; ast.parse(open('src/tui.py').read()); print('Syntax OK')"
```

Expected: `Syntax OK`

**Step 3: Commit**

```bash
cd C:\Users\Honor\Documents\vyos-remnawave && git add src/tui.py && git commit -m "feat: Textual TUI app with status, nodes, config screens"
```

---

### Task 4: Dockerfile

**Files:**
- Create: `Dockerfile`

**Step 1: Create `Dockerfile`**

```dockerfile
# remnawave-sync — VyOS container image
FROM debian:bookworm-slim

# Install runtime deps
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       python3 python3-pip iproute2 ca-certificates curl \
    && pip3 install --no-cache-dir textual \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy Python source
COPY src/ /app/src/
COPY config.env.example /app/

# Create empty __init__.py for package resolution
RUN touch /app/__init__.py /app/src/__init__.py

ENV PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

# Default config location (override via volume)
ENV REMNAWAVE_CONFIG=/etc/remnawave/config.env

# Directories that should be volume-mounted
VOLUME ["/etc/remnawave", "/etc/sing-box", "/var/log/remnawave"]

ENTRYPOINT ["python3", "/app/src/daemon.py"]
CMD ["--config", "/etc/remnawave/config.env"]
```

**Step 2: Verify Dockerfile syntax (no Docker required)**

```bash
cd C:\Users\Honor\Documents\vyos-remnawave && python -c "
lines = open('Dockerfile').read().splitlines()
assert lines[0].startswith('FROM'), 'Missing FROM'
assert any('ENTRYPOINT' in l for l in lines), 'Missing ENTRYPOINT'
assert any('COPY src/' in l for l in lines), 'Missing COPY src/'
print('Dockerfile structure OK')
"
```

Expected: `Dockerfile structure OK`

**Step 3: Commit**

```bash
cd C:\Users\Honor\Documents\vyos-remnawave && git add Dockerfile && git commit -m "feat: Dockerfile for VyOS container deployment"
```

---

### Task 5: GitHub Actions Workflow

**Files:**
- Create: `.github/workflows/docker.yml`

**Step 1: Create directory and workflow file**

```bash
mkdir -p .github/workflows
```

Create `.github/workflows/docker.yml`:

```yaml
name: Build and Push Docker Image

on:
  push:
    branches:
      - main
    tags:
      - 'v*'
  pull_request:
    branches:
      - main

jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write

    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Set up QEMU (for arm64 cross-build)
        uses: docker/setup-qemu-action@v3

      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v3

      - name: Log in to GitHub Container Registry
        if: github.event_name != 'pull_request'
        uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Extract Docker metadata
        id: meta
        uses: docker/metadata-action@v5
        with:
          images: ghcr.io/${{ github.repository }}
          tags: |
            type=ref,event=branch
            type=semver,pattern={{version}}
            type=semver,pattern={{major}}.{{minor}}
            type=raw,value=latest,enable=${{ github.ref == format('refs/heads/{0}', 'main') }}

      - name: Build and push Docker image
        uses: docker/build-push-action@v5
        with:
          context: .
          platforms: linux/amd64,linux/arm64
          push: ${{ github.event_name != 'pull_request' }}
          tags: ${{ steps.meta.outputs.tags }}
          labels: ${{ steps.meta.outputs.labels }}
          cache-from: type=gha
          cache-to: type=gha,mode=max
```

**Step 2: Verify YAML syntax**

```bash
cd C:\Users\Honor\Documents\vyos-remnawave && python -c "
import json
# Use Python's yaml-like check (no pyyaml needed — just check key markers)
content = open('.github/workflows/docker.yml').read()
assert 'docker/build-push-action' in content
assert 'ghcr.io' in content
assert 'linux/amd64,linux/arm64' in content
assert 'GITHUB_TOKEN' in content
print('Workflow file structure OK')
"
```

Expected: `Workflow file structure OK`

**Step 3: Commit**

```bash
cd C:\Users\Honor\Documents\vyos-remnawave && git add .github/ && git commit -m "ci: GitHub Actions multi-arch Docker build to ghcr.io"
```

---

### Task 6: Full Test Suite

**Step 1: Run all tests**

```bash
cd C:\Users\Honor\Documents\vyos-remnawave && python -m pytest tests/ -v --tb=short
```

Expected: All tests PASS (51 existing + new daemon + tui_helpers tests).

**Step 2: Verify tui.py syntax**

```bash
cd C:\Users\Honor\Documents\vyos-remnawave && python -c "import ast; ast.parse(open('src/tui.py').read()); print('tui.py: OK')"
```

**Step 3: Verify daemon.py syntax**

```bash
cd C:\Users\Honor\Documents\vyos-remnawave && python -c "from src.daemon import Daemon, parse_interval; print('daemon.py: OK')"
```

**Step 4: Commit if any fixes**

```bash
cd C:\Users\Honor\Documents\vyos-remnawave && git add -A && git commit -m "test: full suite passing with daemon and TUI helpers"
```

---

## Quick Reference

```bash
# Run TUI locally (needs: pip install textual)
python3 src/tui.py --config /etc/remnawave/config.env

# Run in container
docker exec -it remnawave python3 /app/src/tui.py

# Start daemon directly (container mode)
python3 src/daemon.py --config /etc/remnawave/config.env

# Build Docker image locally
docker build -t remnawave-sync:dev .

# VyOS container setup
set container name remnawave image 'ghcr.io/OWNER/remnawave-sync:latest'
set container name remnawave cap-add 'net-admin'
set container name remnawave device tun source '/dev/net/tun' destination '/dev/net/tun'
set container name remnawave volume config source '/config/remnawave' destination '/etc/remnawave'
set container name remnawave volume singbox source '/config/sing-box' destination '/etc/sing-box'
set container name remnawave volume logs source '/config/remnawave/logs' destination '/var/log/remnawave'
commit ; save
```
