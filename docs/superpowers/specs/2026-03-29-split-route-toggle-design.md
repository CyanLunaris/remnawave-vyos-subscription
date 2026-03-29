# Split-Route Toggle — Design Spec

**Date:** 2026-03-29
**Status:** Approved

---

## Overview

Add a `SPLIT_ROUTE` boolean config key that controls whether geo-based routing rules are active. When `true` (default), Russian IPs/sites bypass the proxy. When `false`, all traffic goes through the proxy. The toggle is exposed in the TUI Config screen (F3) as a `Select` widget.

---

## Config Layer

### New key: `SPLIT_ROUTE`

- **File:** `config.env`
- **Type:** boolean string — `"true"` or `"false"`
- **Default:** `"true"`
- **Validation:** `validate_and_fix_config()` in `sync.py` rejects any value other than `"true"` / `"false"` and resets to `"true"`.
- **`config.env.example`:** add `# SPLIT_ROUTE=true` with a comment explaining the option.

---

## Config Generator

### `ConfigSettings` (`config_generator.py`)

Add field:
```python
split_route: bool = True
```

### `_build_route()` — behaviour when `split_route=False`

Skip all geo-based direct rules and `rule_set` definitions. Only keep:
- `sniff` rule
- `dns` hijack rule
- `ip_is_private` direct rule

Result: all non-private traffic goes to `proxy` outbound.

### `_build_dns()` — behaviour when `split_route=False`

Skip the geosite DNS rule. All DNS queries go to the `remote` server (UDP via proxy).

No `rule_set` array in route, no `.srs` files referenced — so missing geo files cannot cause startup failures even when `SPLIT_ROUTE=false`.

---

## sync.py

`main()` reads `SPLIT_ROUTE` from env and passes it to `ConfigSettings`:
```python
split_route=env.get("SPLIT_ROUTE", "true").lower() != "false",
```

`validate_and_fix_config()` adds validation for `SPLIT_ROUTE`.

---

## heartbeat.py

`_apply_new_node()` reads `SPLIT_ROUTE` and passes it to `ConfigSettings` — same pattern as `sync.py`.

---

## TUI — Config Screen (F3)

### `EDITABLE_KEYS`

Add entry:
```python
("SPLIT_ROUTE", "Split routing (true = RU direct, false = all via proxy)"),
```

### Widget

`SPLIT_ROUTE` uses a Textual `Select` widget with two options (`true`, `false`) instead of a free-text `Input`. The current value from `config.env` is pre-selected.

### Save behaviour

Unchanged — `action_save()` writes all keys to `config.env` and spawns `sync.py` in the background. No new code path needed.

---

## Data Flow

```
User toggles SPLIT_ROUTE in F3 → Save
  → write_config(config_path, {"SPLIT_ROUTE": "false"})
  → spawn sync.py
    → validate_and_fix_config()
    → ConfigSettings(split_route=False)
    → generate_config() → no geo rules in route/dns
    → write config.json
    → reload sing-box
```

Effect is visible within seconds (time for sync.py to run).

---

## Files Changed

| File | Change |
|---|---|
| `src/config_generator.py` | `ConfigSettings.split_route`, conditional geo rules |
| `src/sync.py` | read `SPLIT_ROUTE`, validate |
| `src/heartbeat.py` | read `SPLIT_ROUTE` in `_apply_new_node` |
| `src/tui.py` | add `Select` widget for `SPLIT_ROUTE` in Config screen; pass `split_route` in `NodesScreen.action_switch_node()` |
| `config.env.example` | add commented `SPLIT_ROUTE=true` |

---

## Testing

- `test_config_generator.py`: tests for `split_route=False` producing no geo rules, no rule_set; `split_route=True` producing full geo rules (existing tests already cover this path).
- `test_sync.py`: `validate_and_fix_config` rejects invalid values, defaults missing key to `"true"`.
