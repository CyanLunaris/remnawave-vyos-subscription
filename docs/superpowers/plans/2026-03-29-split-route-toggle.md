# Split-Route Toggle Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `SPLIT_ROUTE=true/false` config key that disables geo-based routing rules so all traffic goes through the proxy, exposed as a `Select` widget in the TUI Config screen (F3).

**Architecture:** `ConfigSettings` gains a `split_route: bool` field consumed by `_build_route()` and `_build_dns()`. `sync.py` and `heartbeat.py` read the env key and pass it through. The TUI Config screen replaces the plain `Input` for this key with a Textual `Select` widget.

**Tech Stack:** Python 3.10+, Textual ≥0.50.0, pytest

---

### Task 1: `ConfigSettings.split_route` — generator logic

**Files:**
- Modify: `src/config_generator.py`
- Modify: `tests/test_config_generator.py`

- [ ] **Step 1: Write failing tests**

Add at the bottom of `tests/test_config_generator.py`:

```python
class TestSplitRoute:
    def test_split_route_true_keeps_geo_rules(self):
        s = ConfigSettings(
            geo_direct_ip=["private", "ru"],
            geo_direct_site=["category-ru"],
            split_route=True,
        )
        cfg = generate_config(make_vless_reality(), s)
        rule_set_tags = [rs["tag"] for rs in cfg["route"].get("rule_set", [])]
        assert any("geoip" in t for t in rule_set_tags)
        assert any("geosite" in t for t in rule_set_tags)

    def test_split_route_false_removes_geo_route_rules(self):
        s = ConfigSettings(
            geo_direct_ip=["private", "ru"],
            geo_direct_site=["category-ru"],
            split_route=False,
        )
        cfg = generate_config(make_vless_reality(), s)
        # No rule_set section in route
        assert "rule_set" not in cfg["route"]
        # No geoip/geosite outbound rules (only sniff, dns, private remain)
        outbound_rules = [
            r for r in cfg["route"]["rules"]
            if r.get("outbound") == "direct" and "rule_set" in r
        ]
        assert outbound_rules == []

    def test_split_route_false_removes_dns_geo_rule(self):
        s = ConfigSettings(
            geo_direct_site=["category-ru"],
            split_route=False,
        )
        cfg = generate_config(make_vless_reality(), s)
        dns_rules = cfg["dns"]["rules"]
        geo_rules = [r for r in dns_rules if "rule_set" in r]
        assert geo_rules == []

    def test_split_route_false_keeps_private_direct(self):
        s = ConfigSettings(split_route=False)
        cfg = generate_config(make_vless_reality(), s)
        private_rule = next(
            (r for r in cfg["route"]["rules"] if r.get("ip_is_private")),
            None,
        )
        assert private_rule is not None
        assert private_rule["outbound"] == "direct"

    def test_split_route_false_keeps_sniff_and_dns_hijack(self):
        s = ConfigSettings(split_route=False)
        cfg = generate_config(make_vless_reality(), s)
        actions = [r.get("action") for r in cfg["route"]["rules"]]
        assert "sniff" in actions
        assert "hijack-dns" in actions

    def test_split_route_defaults_to_true(self):
        s = ConfigSettings()
        assert s.split_route is True
```

- [ ] **Step 2: Run tests to confirm they fail**

```
pytest tests/test_config_generator.py::TestSplitRoute -v
```

Expected: 6 failures — `ConfigSettings` has no `split_route` field.

- [ ] **Step 3: Add `split_route` to `ConfigSettings`**

In `src/config_generator.py`, add the field after `multiplex_max_connections`:

```python
@dataclass
class ConfigSettings:
    tun_interface: str = "tun0"
    tun_address: str = "172.19.0.1/30"
    geo_direct_ip: List[str] = field(default_factory=lambda: ["private", "ru"])
    geo_direct_site: List[str] = field(default_factory=lambda: ["category-ru"])
    rule_set_dir: str = "/etc/sing-box"
    dns_server: str = "8.8.8.8"
    tun_stack: str = "mixed"
    tun_gso: bool = False
    multiplex_protocol: str = ""
    multiplex_max_connections: int = 4
    split_route: bool = True
```

- [ ] **Step 4: Update `_build_route()` to respect `split_route`**

Replace the function in `src/config_generator.py`:

```python
def _build_route(s: ConfigSettings) -> Dict[str, Any]:
    rules: List[Dict[str, Any]] = [
        {"action": "sniff", "timeout": "300ms"},
        {"protocol": "dns", "action": "hijack-dns"},
        {"ip_is_private": True, "outbound": "direct"},
    ]

    rule_set: List[Dict[str, Any]] = []

    if s.split_route:
        non_private = [g for g in s.geo_direct_ip if g != "private"]
        if non_private:
            rules.append({"rule_set": [f"geoip-{code}" for code in non_private], "outbound": "direct"})
        if s.geo_direct_site:
            rules.append({"rule_set": [f"geosite-{code}" for code in s.geo_direct_site], "outbound": "direct"})

        for code in non_private:
            rule_set.append({
                "tag": f"geoip-{code}",
                "type": "local",
                "format": "binary",
                "path": f"{s.rule_set_dir}/geoip-{code}.srs",
            })
        for code in s.geo_direct_site:
            rule_set.append({
                "tag": f"geosite-{code}",
                "type": "local",
                "format": "binary",
                "path": f"{s.rule_set_dir}/geosite-{code}.srs",
            })

    route: Dict[str, Any] = {
        "rules": rules,
        "final": "proxy",
        "default_domain_resolver": "local",
    }
    if rule_set:
        route["rule_set"] = rule_set
    return route
```

- [ ] **Step 5: Update `_build_dns()` to respect `split_route`**

Replace the function in `src/config_generator.py`:

```python
def _build_dns(s: ConfigSettings) -> Dict[str, Any]:
    rules: List[Dict[str, Any]] = []
    if s.split_route and s.geo_direct_site:
        rules.append({
            "rule_set": [f"geosite-{code}" for code in s.geo_direct_site],
            "action": "route",
            "server": "local",
        })
    return {
        "servers": [
            {
                "tag": "remote",
                "type": "udp",
                "server": s.dns_server,
                "detour": "proxy",
                "strategy": "prefer_ipv4",
            },
            {
                "tag": "local",
                "type": "local",
                "strategy": "prefer_ipv4",
            },
        ],
        "rules": rules,
        "final": "remote",
    }
```

- [ ] **Step 6: Run all tests**

```
pytest tests/ -q
```

Expected: all pass.

- [ ] **Step 7: Commit**

```bash
git add src/config_generator.py tests/test_config_generator.py
git commit -m "feat: add split_route to ConfigSettings — skip geo rules when false"
```

---

### Task 2: `sync.py` reads and validates `SPLIT_ROUTE`

**Files:**
- Modify: `src/sync.py`
- Modify: `tests/test_sync.py`

- [ ] **Step 1: Write failing tests**

Add to `tests/test_sync.py` in `TestValidateAndFixConfig`:

```python
def test_split_route_true_kept(self, tmp_path):
    path = self._make_config(tmp_path,
        "SUBSCRIPTION_URL=https://example.com/sub/TOKEN\n"
        "SPLIT_ROUTE=true\n"
    )
    env = validate_and_fix_config(path)
    assert env["SPLIT_ROUTE"] == "true"

def test_split_route_false_kept(self, tmp_path):
    path = self._make_config(tmp_path,
        "SUBSCRIPTION_URL=https://example.com/sub/TOKEN\n"
        "SPLIT_ROUTE=false\n"
    )
    env = validate_and_fix_config(path)
    assert env["SPLIT_ROUTE"] == "false"

def test_split_route_invalid_reset_to_true(self, tmp_path):
    path = self._make_config(tmp_path,
        "SUBSCRIPTION_URL=https://example.com/sub/TOKEN\n"
        "SPLIT_ROUTE=yes\n"
    )
    env = validate_and_fix_config(path)
    assert env["SPLIT_ROUTE"] == "true"

def test_split_route_missing_defaults_to_true(self, tmp_path):
    path = self._make_config(tmp_path,
        "SUBSCRIPTION_URL=https://example.com/sub/TOKEN\n"
    )
    env = validate_and_fix_config(path)
    assert env["SPLIT_ROUTE"] == "true"
```

- [ ] **Step 2: Run tests to confirm they fail**

```
pytest tests/test_sync.py::TestValidateAndFixConfig::test_split_route_true_kept tests/test_sync.py::TestValidateAndFixConfig::test_split_route_false_kept tests/test_sync.py::TestValidateAndFixConfig::test_split_route_invalid_reset_to_true tests/test_sync.py::TestValidateAndFixConfig::test_split_route_missing_defaults_to_true -v
```

Expected: failures — `SPLIT_ROUTE` not validated/defaulted yet.

- [ ] **Step 3: Add `SPLIT_ROUTE` to `_DEFAULTS` in `sync.py`**

In `src/sync.py`, add to `_DEFAULTS`:

```python
_DEFAULTS: dict = {
    ...
    "SPLIT_ROUTE": "true",
}
```

- [ ] **Step 4: Add `SPLIT_ROUTE` validation in `validate_and_fix_config()`**

In `src/sync.py`, inside `validate_and_fix_config()`, after the multiplex protocol check, add:

```python
sr = env.get("SPLIT_ROUTE", "")
if sr not in ("true", "false"):
    fixes["SPLIT_ROUTE"] = "true"
    if sr:
        log.warning("Config: SPLIT_ROUTE=%r is invalid — resetting to 'true'", sr)
```

- [ ] **Step 5: Pass `split_route` to `ConfigSettings` in `sync.main()`**

In `src/sync.py`, update the `ConfigSettings(...)` call in `main()`:

```python
settings = ConfigSettings(
    tun_interface=env.get("TUN_INTERFACE", "tun0"),
    tun_address=env.get("TUN_ADDRESS", "172.19.0.1/30"),
    geo_direct_ip=env.get("GEO_DIRECT_IP", "private,ru").split(","),
    geo_direct_site=env.get("GEO_DIRECT_SITE", "category-ru").split(","),
    rule_set_dir=rule_set_dir,
    tun_stack=env.get("TUN_STACK", "mixed"),
    tun_gso=env.get("TUN_GSO", "").lower() in ("1", "true", "yes"),
    multiplex_protocol=env.get("MULTIPLEX_PROTOCOL", ""),
    multiplex_max_connections=int(env.get("MULTIPLEX_MAX_CONNECTIONS", "4")),
    split_route=env.get("SPLIT_ROUTE", "true").lower() != "false",
)
```

- [ ] **Step 6: Run all tests**

```
pytest tests/ -q
```

Expected: all pass.

- [ ] **Step 7: Commit**

```bash
git add src/sync.py tests/test_sync.py
git commit -m "feat: read and validate SPLIT_ROUTE in sync.py"
```

---

### Task 3: `heartbeat.py` passes `split_route`

**Files:**
- Modify: `src/heartbeat.py`
- Modify: `tests/test_heartbeat.py`

- [ ] **Step 1: Write failing test**

Read `tests/test_heartbeat.py` first, then add to the existing test class:

```python
def test_apply_new_node_respects_split_route_false(self, tmp_path):
    """Config regenerated after node rotation must honour SPLIT_ROUTE=false."""
    config = tmp_path / "config.env"
    config.write_text(
        "SUBSCRIPTION_URL=https://example.com/sub/TOKEN\n"
        "SPLIT_ROUTE=false\n"
        f"NODES_FILE={tmp_path}/nodes.json\n"
        f"STATE_FILE={tmp_path}/state.json\n"
        f"XRAY_CONFIG={tmp_path}/config.json\n"
    )
    node = ParsedNode(
        protocol="vless", host="nl1.example.com", port=443,
        uuid="test-uuid", security="reality", network="tcp",
        reality_pbk="KEY", reality_sid="abc", sni="microsoft.com",
        fingerprint="chrome",
    )
    sm = StateManager(str(tmp_path / "nodes.json"), str(tmp_path / "state.json"))
    sm.save_nodes([node])

    with patch("src.tui_helpers.reload_sing_box", return_value=True):
        _apply_new_node(sm, str(config))

    written = json.loads((tmp_path / "config.json").read_text())
    assert "rule_set" not in written["route"]
```

Add required imports at the top of `tests/test_heartbeat.py` if missing:
```python
import json
from src.heartbeat import _apply_new_node
from src.state_manager import StateManager
from src.uri_parser import ParsedNode
```

- [ ] **Step 2: Run test to confirm it fails**

```
pytest tests/test_heartbeat.py::test_apply_new_node_respects_split_route_false -v
```

Expected: FAIL — `_apply_new_node` doesn't pass `split_route` yet.

- [ ] **Step 3: Update `_apply_new_node()` in `heartbeat.py`**

In `src/heartbeat.py`, update the `ConfigSettings(...)` call inside `_apply_new_node()`:

```python
settings = ConfigSettings(
    tun_interface=env.get("TUN_INTERFACE", "tun0"),
    tun_address=env.get("TUN_ADDRESS", "172.19.0.1/30"),
    geo_direct_ip=env.get("GEO_DIRECT_IP", "private,ru").split(","),
    geo_direct_site=env.get("GEO_DIRECT_SITE", "category-ru").split(","),
    rule_set_dir=env.get("RULE_SET_DIR", "/etc/sing-box"),
    tun_stack=env.get("TUN_STACK", "mixed"),
    tun_gso=env.get("TUN_GSO", "").lower() in ("1", "true", "yes"),
    multiplex_protocol=env.get("MULTIPLEX_PROTOCOL", ""),
    multiplex_max_connections=int(env.get("MULTIPLEX_MAX_CONNECTIONS", "4")),
    split_route=env.get("SPLIT_ROUTE", "true").lower() != "false",
)
```

- [ ] **Step 4: Run all tests**

```
pytest tests/ -q
```

Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add src/heartbeat.py tests/test_heartbeat.py
git commit -m "feat: pass split_route through heartbeat node rotation"
```

---

### Task 4: TUI — `Select` widget in Config screen + `NodesScreen` fix

**Files:**
- Modify: `src/tui.py`

No automated tests for TUI widgets (Textual requires a running event loop). Verification is manual.

- [ ] **Step 1: Add `Select` import to `tui.py`**

In `src/tui.py`, update the Textual widget imports to include `Select`:

```python
from textual.widgets import (
    Button, DataTable, Footer, Header, Input, Label,
    Select, Static, TabbedContent, TabPane,
)
```

- [ ] **Step 2: Add `SPLIT_ROUTE` to `EDITABLE_KEYS`**

`EDITABLE_KEYS` in `src/tui.py` currently ends after `GEO_DIRECT_SITE`. Add the split-route entry — use a sentinel tuple with a third element to mark it as a select field:

```python
EDITABLE_KEYS = [
    ("SUBSCRIPTION_URL", "Subscription URL (sub-link)", "input"),
    ("SYNC_INTERVAL", "Sync interval (e.g. 10min)", "input"),
    ("HEARTBEAT_INTERVAL", "Heartbeat interval (e.g. 30s)", "input"),
    ("HEARTBEAT_FAIL_THRESHOLD", "Fail threshold (number)", "input"),
    ("GEO_DIRECT_IP", "Direct GeoIP (e.g. private,ru)", "input"),
    ("GEO_DIRECT_SITE", "Direct GeoSite (e.g. ru)", "input"),
    ("SPLIT_ROUTE", "Split routing (RU direct / all via proxy)", "select"),
]
```

- [ ] **Step 3: Update `ConfigScreen.compose()` to render `Select` for boolean keys**

Replace the `compose` method of `ConfigScreen`:

```python
def compose(self) -> ComposeResult:
    cfg = read_config(self.config_path)
    yield Header(show_clock=False)
    with Vertical():
        for key, label, widget_type in EDITABLE_KEYS:
            yield Label(label)
            if widget_type == "select":
                current = cfg.get(key, "true")
                yield Select(
                    [("true — RU goes direct", "true"), ("false — all via proxy", "false")],
                    value=current if current in ("true", "false") else "true",
                    id=f"input-{key}",
                )
            else:
                yield Input(value=cfg.get(key, ""), id=f"input-{key}")
        yield Horizontal(
            Button("Save & Sync", variant="success", id="btn-save"),
            Button("Cancel", id="btn-cancel"),
        )
    yield Footer()
```

- [ ] **Step 4: Update `action_save()` to read `Select` value**

Replace `action_save` in `ConfigScreen`:

```python
def action_save(self) -> None:
    updates = {}
    for key, _, widget_type in EDITABLE_KEYS:
        if widget_type == "select":
            sel = self.query_one(f"#input-{key}", Select)
            updates[key] = str(sel.value) if sel.value is not Select.BLANK else "true"
        else:
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
```

- [ ] **Step 5: Pass `split_route` in `NodesScreen.action_switch_node()`**

In `NodesScreen.action_switch_node()`, update the `ConfigSettings(...)` call:

```python
settings = ConfigSettings(
    tun_interface=env.get("TUN_INTERFACE", "tun0"),
    tun_address=env.get("TUN_ADDRESS", "172.19.0.1/30"),
    geo_direct_ip=env.get("GEO_DIRECT_IP", "private,ru").split(","),
    geo_direct_site=env.get("GEO_DIRECT_SITE", "category-ru").split(","),
    rule_set_dir=env.get("RULE_SET_DIR", "/etc/sing-box"),
    tun_stack=env.get("TUN_STACK", "mixed"),
    tun_gso=env.get("TUN_GSO", "").lower() in ("1", "true", "yes"),
    multiplex_protocol=env.get("MULTIPLEX_PROTOCOL", ""),
    multiplex_max_connections=int(env.get("MULTIPLEX_MAX_CONNECTIONS", "4")),
    split_route=env.get("SPLIT_ROUTE", "true").lower() != "false",
)
```

- [ ] **Step 6: Run all tests**

```
pytest tests/ -q
```

Expected: all pass (TUI changes don't affect unit tests).

- [ ] **Step 7: Commit**

```bash
git add src/tui.py
git commit -m "feat: add SPLIT_ROUTE Select widget to Config screen (F3)"
```

---

### Task 5: `config.env.example` + final verification

**Files:**
- Modify: `config.env.example`

- [ ] **Step 1: Add `SPLIT_ROUTE` entry to `config.env.example`**

Open `config.env.example` and add after the `GEO_DIRECT_SITE` line:

```bash
# Route Russian IPs and sites directly, everything else via proxy.
# Set to false to route ALL traffic through the proxy (useful for testing
# or when you want full anonymity / no geo-bypass).
# SPLIT_ROUTE=true
```

- [ ] **Step 2: Run full test suite one final time**

```
pytest tests/ -q
```

Expected: all pass.

- [ ] **Step 3: Final commit**

```bash
git add config.env.example
git commit -m "docs: document SPLIT_ROUTE option in config.env.example"
```

---

## Self-Review

**Spec coverage:**
- `ConfigSettings.split_route` → Task 1 ✓
- `_build_route` skips geo when `False` → Task 1 ✓
- `_build_dns` skips geo rule when `False` → Task 1 ✓
- `sync.py` reads + validates → Task 2 ✓
- `heartbeat.py` passes `split_route` → Task 3 ✓
- TUI Config screen `Select` widget → Task 4 ✓
- `NodesScreen` passes `split_route` → Task 4 step 5 ✓
- `config.env.example` entry → Task 5 ✓

**Placeholder scan:** No TBD/TODO/vague steps — all steps contain exact code.

**Type consistency:**
- `split_route: bool = True` defined in Task 1, consumed as `bool` everywhere ✓
- `EDITABLE_KEYS` tuple changes from 2-element to 3-element in Task 4 step 2 — `compose()` and `action_save()` both updated in same task ✓
- `Select.BLANK` sentinel used in `action_save()` — correct Textual API for "no selection" ✓
