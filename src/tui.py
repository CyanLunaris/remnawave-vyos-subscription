#!/usr/bin/env python3
"""
remnaproxy TUI — manage the proxy service from a terminal.

Usage:
  python3 tui.py [--config /etc/remnaproxy/config.env]

Requires: pip install textual
"""
from __future__ import annotations
import argparse
import subprocess
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from textual.app import App, ComposeResult
    from textual.binding import Binding
    from textual.containers import Container, Horizontal, Vertical
    from textual.screen import Screen, ModalScreen
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
    get_last_log_line, reload_proxy,
)
from src.state_manager import StateManager
from src.config_generator import ConfigSettings, generate_config
from src.xray_config_generator import generate_xray_config
from src.sync import load_env
import json


# ── Status Panel ─────────────────────────────────────────────────────────────

STATUS_CSS = """
.status-row { height: 1; }
.label      { width: 20; color: $text-muted; }
.value      { color: $success; }
.value-warn { color: $warning; }
.value-err  { color: $error; }
"""


def _read_xray_version() -> str:
    try:
        return Path("/etc/xray/.version").read_text().strip()
    except Exception:
        return "?.?.?"


class StatusPanel(Static):
    """Shows proxy status, current node, kernel version."""

    DEFAULT_CSS = STATUS_CSS

    def __init__(self, config_path: str, **kwargs):
        super().__init__(**kwargs)
        self.config_path = config_path
        env = load_env(config_path)
        self._nodes_file = env.get("NODES_FILE", "/etc/remnaproxy/nodes.json")
        self._state_file = env.get("STATE_FILE", "/etc/remnaproxy/state.json")
        self._log_dir = env.get("LOG_DIR", "/var/log/remnaproxy")
        self._kernel = env.get("PROXY_KERNEL", "singbox")

    def compose(self) -> ComposeResult:
        st = get_status(self._nodes_file, self._state_file)
        sync_last = get_last_log_line(f"{self._log_dir}/sync.log") or "—"
        hb_last = get_last_log_line(f"{self._log_dir}/heartbeat.log") or "—"
        fail = st["fail_count"]
        fail_class = "value-err" if fail >= 2 else ("value-warn" if fail > 0 else "value")

        if self._kernel == "xray":
            ver = _read_xray_version()
            kernel_str = f"xray v{ver}"
        else:
            kernel_str = "sing-box"

        yield Label(f"Kernel       : {kernel_str}", classes="status-row value")
        yield Label(f"Current node : {st['current_node_name']}  "
                    f"({st['current_node_host']}:{st['current_node_port']})",
                    classes="status-row value")
        yield Label(f"Protocol     : {st['current_node_protocol']}",
                    classes="status-row value")
        yield Label(f"Node index   : {st['current_index'] + 1} / {st['node_count']}",
                    classes="status-row value")
        yield Label(f"Fail count   : {fail}", classes=f"status-row {fail_class}")
        yield Label(f"Last sync    : {sync_last[-80:]}", classes="status-row value")
        yield Label(f"Last hb      : {hb_last[-80:]}", classes="status-row value")


# ── Nodes Screen ──────────────────────────────────────────────────────────────

class NodesScreen(Screen):
    BINDINGS = [
        Binding("enter", "switch_node", "Switch to selected", priority=True),
        Binding("escape", "app.pop_screen", "Back"),
    ]

    def __init__(self, config_path: str, **kwargs):
        super().__init__(**kwargs)
        self.config_path = config_path
        env = load_env(config_path)
        self._nodes_file = env.get("NODES_FILE", "/etc/remnaproxy/nodes.json")
        self._state_file = env.get("STATE_FILE", "/etc/remnaproxy/state.json")
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
        table.focus()
        if current < table.row_count:
            table.move_cursor(row=current)

    def action_switch_node(self) -> None:
        table = self.query_one(DataTable)
        if table.row_count == 0:
            return
        idx = table.cursor_row
        self._sm.set_current_index(idx)
        self._sm.reset_fail_count()

        node = self._sm.get_current_node()
        if node:
            env = load_env(self.config_path)
            kernel = env.get("PROXY_KERNEL", "singbox")
            settings = ConfigSettings(
                tun_interface=env.get("TUN_INTERFACE", "tun0"),
                tun_address=env.get("TUN_ADDRESS", "172.19.0.1/30"),
                geo_direct_ip=env.get("GEO_DIRECT_IP", "private,ru").split(","),
                geo_direct_site=env.get("GEO_DIRECT_SITE", "category-ru").split(","),
                rule_set_dir=env.get("RULE_SET_DIR", "/etc/sing-box"),
            )
            if kernel == "xray":
                config = generate_xray_config(node, settings)
                config_file = env.get("XRAY_CONFIG_FILE", "/etc/xray/xray-config.json")
            else:
                config = generate_config(node, settings)
                config_file = env.get("XRAY_CONFIG", "/etc/sing-box/config.json")
            Path(config_file).parent.mkdir(parents=True, exist_ok=True)
            Path(config_file).write_text(json.dumps(config, indent=2))
            reload_proxy(kernel)
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


# ── Kernel Switch Modal ───────────────────────────────────────────────────────

class KernelSwitchModal(ModalScreen):
    """Non-closeable progress modal for kernel switching."""

    DEFAULT_CSS = """
    KernelSwitchModal {
        align: center middle;
    }
    KernelSwitchModal > Vertical {
        width: 60;
        height: auto;
        padding: 1 2;
        border: solid $primary;
        background: $surface;
    }
    #modal-title  { text-style: bold; margin-bottom: 1; }
    #modal-log    { height: 10; overflow-y: auto; }
    #modal-status { margin-top: 1; }
    #modal-close  { margin-top: 1; display: none; }
    """

    def __init__(self, daemon, new_kernel: str, **kwargs):
        super().__init__(**kwargs)
        self._daemon = daemon
        self._new_kernel = new_kernel

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label(f"Switching to {self._new_kernel}...", id="modal-title")
            yield Static("", id="modal-log")
            yield Label("", id="modal-status")
            yield Button("Close", id="modal-close")

    def on_mount(self) -> None:
        threading.Thread(target=self._do_switch, daemon=True).start()

    def _do_switch(self) -> None:
        def append(line: str) -> None:
            self.call_from_thread(self._append_log, line)

        try:
            self._daemon.restart_kernel(self._new_kernel, log_callback=append)
            self.call_from_thread(self._on_success)
        except Exception as exc:
            self.call_from_thread(self._on_failure, str(exc))

    def _append_log(self, line: str) -> None:
        log_widget = self.query_one("#modal-log", Static)
        current = str(log_widget.renderable)
        log_widget.update(current + "\n" + line if current else line)

    def _on_success(self) -> None:
        self.query_one("#modal-status", Label).update("Done.")
        self.query_one("#modal-close", Button).styles.display = "block"
        # Refresh main app status panel
        self.app.query_one(StatusPanel).refresh(layout=True)

    def _on_failure(self, error: str) -> None:
        self.query_one("#modal-status", Label).update(f"Error: {error}")
        self.query_one("#modal-close", Button).styles.display = "block"

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "modal-close":
            self.dismiss()


# ── Settings Screen ───────────────────────────────────────────────────────────

class SettingsScreen(Screen):
    BINDINGS = [Binding("escape", "app.pop_screen", "Back")]

    DEFAULT_CSS = """
    SettingsScreen #kernel-row { height: 3; margin: 1 2; }
    SettingsScreen .kernel-btn-active { background: $primary; }
    """

    def __init__(self, config_path: str, daemon, **kwargs):
        super().__init__(**kwargs)
        self.config_path = config_path
        self._daemon = daemon
        self._kernel = load_env(config_path).get("PROXY_KERNEL", "singbox")

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        with Vertical():
            yield Label("Proxy Kernel")
            with Horizontal(id="kernel-row"):
                sb_cls = "kernel-btn-active" if self._kernel != "xray" else ""
                xr_cls = "kernel-btn-active" if self._kernel == "xray" else ""
                yield Button("sing-box", id="btn-singbox", classes=sb_cls)
                yield Button("xray", id="btn-xray", classes=xr_cls)
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-singbox":
            self._switch_kernel("singbox")
        elif event.button.id == "btn-xray":
            self._switch_kernel("xray")

    def _switch_kernel(self, kernel: str) -> None:
        current = load_env(self.config_path).get("PROXY_KERNEL", "singbox")
        if kernel == current:
            return
        self.app.push_screen(KernelSwitchModal(self._daemon, kernel))


# ── Main App ──────────────────────────────────────────────────────────────────

class RemnaApp(App):
    """remnaproxy-sync TUI."""

    CSS = """
    StatusPanel { height: auto; padding: 1 2; }
    DataTable   { height: 1fr; }
    Button      { margin: 0 1; }
    """

    BINDINGS = [
        Binding("f2", "push_screen('nodes')", "Nodes"),
        Binding("f3", "push_screen('config')", "Config"),
        Binding("f4", "push_screen('settings')", "Settings"),
        Binding("s", "force_sync", "Force Sync"),
        Binding("q", "quit", "Quit"),
    ]

    def __init__(self, config_path: str, daemon=None, **kwargs):
        super().__init__(**kwargs)
        self.config_path = config_path
        self._daemon = daemon

    def compose(self) -> ComposeResult:
        yield Header()
        yield StatusPanel(self.config_path)
        yield Footer()

    def on_mount(self) -> None:
        self.install_screen(NodesScreen(self.config_path), name="nodes")
        self.install_screen(ConfigScreen(self.config_path), name="config")
        self.install_screen(
            SettingsScreen(self.config_path, self._daemon), name="settings"
        )

    def action_force_sync(self) -> None:
        subprocess.Popen([
            sys.executable,
            str(Path(__file__).parent / "sync.py"),
            "--config", self.config_path,
        ])
        self.notify("Sync triggered", severity="information")


def main(config_path: str = "/etc/remnaproxy/config.env", daemon=None) -> None:
    app = RemnaApp(config_path, daemon=daemon)
    app.run()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="/etc/remnaproxy/config.env")
    args = parser.parse_args()
    main(args.config)
