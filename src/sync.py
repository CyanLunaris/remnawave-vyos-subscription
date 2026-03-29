#!/usr/bin/env python3
"""
remnaproxy-sync — fetch subscription and update sing-box config.

Usage:
  python3 sync.py [--config /etc/remnaproxy/config.env]
"""
from __future__ import annotations
import argparse
import hashlib
import ipaddress
import json
import logging
import os
import sys
from pathlib import Path

# Allow running directly as script
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.binary_manager import ensure_sing_box, ensure_rule_sets
from src.config_generator import ConfigSettings, generate_config
from src.state_manager import StateManager
from src.subscription import fetch_subscription

log = logging.getLogger("remnaproxy-sync")

# ── Config defaults used for validation / auto-fix ───────────────────────────

_DEFAULTS: dict = {
    "SYNC_INTERVAL": "10min",
    "HEARTBEAT_INTERVAL": "30s",
    "HEARTBEAT_FAIL_THRESHOLD": "2",
    "HEARTBEAT_TIMEOUT": "5",
    "HEARTBEAT_COOLDOWN": "2",
    "TUN_INTERFACE": "tun0",
    "TUN_ADDRESS": "172.19.0.1/30",
    "TUN_STACK": "mixed",
    "TUN_GSO": "false",
    "XRAY_BIN": "/usr/local/bin/sing-box",
    "XRAY_CONFIG": "/etc/sing-box/config.json",
    "NODES_FILE": "/etc/remnaproxy/nodes.json",
    "STATE_FILE": "/etc/remnaproxy/state.json",
    "LOG_DIR": "/var/log/remnaproxy",
    "RULE_SET_DIR": "/etc/sing-box",
    "GEO_DIRECT_IP": "private,ru",
    "GEO_DIRECT_SITE": "category-ru",
    "MULTIPLEX_MAX_CONNECTIONS": "4",
    "SPLIT_ROUTE": "true",
}

_VALID_TUN_STACKS = {"mixed", "system", "gvisor"}
_VALID_MULTIPLEX = {"smux", "yamux", "h2mux", ""}


def load_env(path: str) -> dict:
    env: dict = {}
    try:
        for line in Path(path).read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            env[key.strip()] = value.strip()
    except FileNotFoundError:
        pass
    return env


def parse_interval(s: str) -> int:
    """Parse '10min', '30s', or bare seconds string to int seconds."""
    s = s.strip()
    if s.endswith("min"):
        return int(s[:-3]) * 60
    if s.endswith("s"):
        return int(s[:-1])
    return int(s)


def _is_valid_interval(s: str) -> bool:
    try:
        parse_interval(s)
        return True
    except (ValueError, AttributeError):
        return False


def _is_valid_cidr(s: str) -> bool:
    try:
        ipaddress.ip_interface(s)
        return True
    except ValueError:
        return False


def validate_and_fix_config(config_path: str) -> dict:
    """Read config, auto-fix invalid values, rewrite file if needed.

    Returns the final validated env dict (only keys from the file, not os.environ).
    Logs every fix applied so the user knows what changed.
    """
    fixes: dict = {}
    env = load_env(config_path)

    def _check(key: str, validator, default: str) -> None:
        val = env.get(key, "")
        if not val:
            if key in _DEFAULTS:
                fixes[key] = _DEFAULTS[key]
                log.warning("Config: %s missing — setting default %s", key, _DEFAULTS[key])
        elif not validator(val):
            fixes[key] = default
            log.warning("Config: %s=%r is invalid — resetting to %r", key, val, default)

    # Interval fields
    for key, default in [
        ("SYNC_INTERVAL", "10min"),
        ("HEARTBEAT_INTERVAL", "30s"),
    ]:
        _check(key, _is_valid_interval, default)

    # Positive integer fields
    def _pos_int(s: str) -> bool:
        try:
            return int(s) > 0
        except ValueError:
            return False

    def _nonneg_int(s: str) -> bool:
        try:
            return int(s) >= 0
        except ValueError:
            return False

    for key, validator, default in [
        ("HEARTBEAT_FAIL_THRESHOLD", _pos_int, "2"),
        ("HEARTBEAT_TIMEOUT", _pos_int, "5"),
        ("HEARTBEAT_COOLDOWN", _nonneg_int, "2"),
        ("MULTIPLEX_MAX_CONNECTIONS", _pos_int, "4"),
    ]:
        _check(key, validator, default)

    # TUN address
    _check("TUN_ADDRESS", _is_valid_cidr, "172.19.0.1/30")

    # TUN stack
    _check("TUN_STACK", lambda s: s in _VALID_TUN_STACKS, "mixed")

    # TUN interface (non-empty string)
    _check("TUN_INTERFACE", lambda s: bool(s.strip()), "tun0")

    # Multiplex protocol
    mp = env.get("MULTIPLEX_PROTOCOL", "")
    if mp and mp not in _VALID_MULTIPLEX:
        fixes["MULTIPLEX_PROTOCOL"] = ""
        log.warning("Config: MULTIPLEX_PROTOCOL=%r is invalid — clearing", mp)

    # Split route
    sr = env.get("SPLIT_ROUTE", "")
    if sr not in ("true", "false"):
        fixes["SPLIT_ROUTE"] = "true"
        if sr:
            log.warning("Config: SPLIT_ROUTE=%r is invalid — resetting to 'true'", sr)
        else:
            log.warning("Config: SPLIT_ROUTE missing — setting default 'true'")

    # Apply defaults for missing optional keys
    for key, default in _DEFAULTS.items():
        if key not in env and key not in fixes:
            fixes[key] = default

    # Write fixes back to file
    if fixes:
        log.info("Config: writing %d fix(es) to %s", len(fixes), config_path)
        _write_config_updates(config_path, fixes)
        env.update(fixes)

    if not env.get("SUBSCRIPTION_URL", "").strip():
        log.error("Config: SUBSCRIPTION_URL is not set in %s", config_path)

    return env


def _write_config_updates(config_path: str, updates: dict) -> None:
    """Update specific keys in config file, preserving all other lines."""
    import os
    import tempfile

    path = Path(config_path)
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True) if path.exists() else []

    updated_keys: set = set()
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

    for key, value in updates.items():
        if key not in updated_keys:
            new_lines.append(f"{key}={value}\n")

    content = "".join(new_lines)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=path.parent, prefix=".tmp-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
        os.replace(tmp_path, str(path))
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def _setup_logging(log_dir: str) -> None:
    """Add a file handler for this module's logger (idempotent).

    When called from the daemon (which has already configured the root logger),
    this adds a dedicated sync.log file handler so messages are captured there
    as well as in the root daemon.log.  When running standalone, it also sets up
    a basic console handler on the root logger.
    """
    Path(log_dir).mkdir(parents=True, exist_ok=True)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    # Add file handler to this module's logger (only once)
    if not any(
        isinstance(h, logging.FileHandler) and h.baseFilename.endswith("sync.log")
        for h in log.handlers
    ):
        fh = logging.FileHandler(f"{log_dir}/sync.log")
        fh.setFormatter(fmt)
        log.addHandler(fh)
        log.setLevel(logging.INFO)

    # If running standalone (no root handlers yet), add console output
    if not logging.root.handlers:
        sh = logging.StreamHandler()
        sh.setFormatter(fmt)
        logging.root.addHandler(sh)
        logging.root.setLevel(logging.INFO)


def main(config_path: str = "/etc/remnaproxy/config.env") -> int:
    # Validate and auto-fix config before doing anything
    cfg = validate_and_fix_config(config_path)

    log_dir = cfg.get("LOG_DIR", "/var/log/remnaproxy")
    _setup_logging(log_dir)

    env = {**os.environ, **cfg}  # env file takes precedence over os.environ

    subscription_url = env.get("SUBSCRIPTION_URL", "")
    if not subscription_url:
        log.error("SUBSCRIPTION_URL not set in %s", config_path)
        return 1

    sing_box_bin  = env.get("XRAY_BIN", "/usr/local/bin/sing-box")
    xray_config   = env.get("XRAY_CONFIG", "/etc/sing-box/config.json")
    nodes_file    = env.get("NODES_FILE", "/etc/remnaproxy/nodes.json")
    state_file    = env.get("STATE_FILE", "/etc/remnaproxy/state.json")
    rule_set_dir  = env.get("RULE_SET_DIR", "/etc/sing-box")

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

    sm = StateManager(nodes_file, state_file)

    # 1. Ensure sing-box binary is present (downloads if missing)
    try:
        ensure_sing_box(sing_box_bin)
    except Exception as exc:
        log.error("Failed to ensure sing-box binary: %s", exc)
        return 1

    # 2. Ensure geo rule-set files are present (downloads if missing)
    # "private" is handled by ip_is_private routing rule, has no .srs file
    non_private_ip = [g for g in settings.geo_direct_ip if g != "private"]
    try:
        ensure_rule_sets(rule_set_dir, non_private_ip, settings.geo_direct_site)
    except Exception as exc:
        log.warning("Failed to download some rule-set files: %s", exc)
        # Non-fatal — continue with whatever rule-set files are already present

    # 3. Fetch subscription
    try:
        nodes = fetch_subscription(subscription_url)
        log.info("Fetched %d nodes from subscription", len(nodes))
    except ConnectionError as exc:
        log.warning("Subscription fetch failed: %s — using cached nodes", exc)
        nodes = sm.load_nodes()
        if not nodes:
            log.error("No cached nodes available")
            return 1

    if not nodes:
        log.error("Subscription returned 0 nodes")
        return 1

    # 4. Update nodes cache (reset index if node count changed)
    old_nodes = sm.load_nodes()
    sm.save_nodes(nodes)
    if len(nodes) != len(old_nodes):
        sm.set_current_index(0)
        log.info("Node list changed (%d → %d), reset to node 0", len(old_nodes), len(nodes))

    # 5. Generate config for current node
    current_node = sm.get_current_node()
    if current_node is None:
        log.error("No current node")
        return 1

    log.info("Generating config for node: %s (%s:%d)", current_node.name, current_node.host, current_node.port)
    config = generate_config(current_node, settings)
    config_json = json.dumps(config, indent=2)

    # 6. Compare with existing config — only restart if changed
    config_path_obj = Path(xray_config)
    config_path_obj.parent.mkdir(parents=True, exist_ok=True)

    old_hash = _hash_file(xray_config)
    new_hash = hashlib.sha256(config_json.encode()).hexdigest()

    if old_hash == new_hash:
        log.info("Config unchanged, no restart needed")
        return 0

    config_path_obj.write_text(config_json)
    log.info("Config written to %s", xray_config)

    # 7. Reload/start sing-box
    _reload_sing_box()
    return 0


def _hash_file(path: str) -> str:
    try:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    except FileNotFoundError:
        return ""


def _reload_sing_box() -> None:
    from src.tui_helpers import reload_sing_box
    if reload_sing_box():
        log.info("sing-box reloaded")
    else:
        log.error("sing-box reload failed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="/etc/remnaproxy/config.env")
    args = parser.parse_args()
    sys.exit(main(args.config))
