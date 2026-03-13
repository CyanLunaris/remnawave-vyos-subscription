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


class StatusPanel(Static):
    """Shows sing-box status, current node, fail count."""

    DEFAULT_CSS = STATUS_CSS

    def __init__(self, config_path: str, **kwargs):
        super().__init__(**kwargs)
        self.config_path = config_path
        env = load_env(config_path)
        self._nodes_file = env.get("NODES_FILE", "/etc/remnaproxy/nodes.json")
        self._state_file = env.get("STATE_FILE", "/etc/remnaproxy/state.json")
        self._log_dir = env.get("LOG_DIR", "/var/log/remnaproxy")

    def compose(self) -> ComposeResult:
        st = get_status(self._nodes_file, self._state_file)
        sync_last = get_last_log_line(f"{self._log_dir}/sync.log") or "—"
        hb_last = get_last_log_line(f"{self._log_dir}/heartbeat.log") or "—"
        fail = st["fail_count"]
        fail_class = "value-err" if fail >= 2 else ("value-warn" if fail > 0 else "value")

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
        Binding("enter", "switch_node", "Switch to selected"),
        Binding("escape", "app.pop_screen", "Back"),
    ]

    def __init__(self, config_path: str, **kwargs):
        super().__init__(**kwargs)
        self.config_path = config_path
        env = load_env(config_path)
        self._nodes_file = env.get("NODES_FILE", "/etc/remnaproxy/nodes.json")
        self._state_file = env.get("STATE_FILE", "/etc/remnaproxy/state.json")
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
        table.focus()
        if current < table.row_count:
            table.move_cursor(row=current)

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        self.action_switch_node()

    def action_switch_node(self) -> None:
        table = self.query_one(DataTable)
        if table.row_count == 0:
            return
        idx = table.cursor_row
        self._sm.set_current_index(idx)

        # Regenerate config
        node = self._sm.get_current_node()
        if node:
            env = load_env(self.config_path)
            settings = ConfigSettings(
                tun_interface=env.get("TUN_INTERFACE", "tun0"),
                tun_address=env.get("TUN_ADDRESS", "172.19.0.1/30"),
                geo_direct_ip=env.get("GEO_DIRECT_IP", "private,ru").split(","),
                geo_direct_site=env.get("GEO_DIRECT_SITE", "category-ru").split(","),
                rule_set_dir=env.get("RULE_SET_DIR", "/etc/sing-box"),
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
    """remnaproxy-sync TUI."""

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


def main(config_path: str = "/etc/remnaproxy/config.env") -> None:
    app = RemnaApp(config_path)
    app.run()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="/etc/remnaproxy/config.env")
    args = parser.parse_args()
    main(args.config)
