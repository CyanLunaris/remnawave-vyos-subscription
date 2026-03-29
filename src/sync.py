#!/usr/bin/env python3
"""
remnaproxy-sync — fetch subscription and update proxy kernel config.

Usage:
  python3 sync.py [--config /etc/remnaproxy/config.env]
"""
from __future__ import annotations
import argparse
import hashlib
import json
import logging
import os
import sys
from pathlib import Path
from typing import Callable, Optional

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.binary_manager import (
    ensure_sing_box, ensure_rule_sets,
    ensure_xray, ensure_tun2socks, ensure_xray_rule_sets,
)
from src.config_generator import ConfigSettings, generate_config
from src.xray_config_generator import generate_xray_config
from src.state_manager import StateManager
from src.subscription import fetch_subscription

log = logging.getLogger("remnaproxy-sync")


def load_env(path: str) -> dict:
    env = {}
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


def main(config_path: str = "/etc/remnaproxy/config.env",
         log_callback: Optional[Callable[[str], None]] = None) -> int:
    env = load_env(config_path)
    env = {**os.environ, **env}

    log_dir = env.get("LOG_DIR", "/var/log/remnaproxy")
    Path(log_dir).mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[
            logging.FileHandler(f"{log_dir}/sync.log"),
            logging.StreamHandler(),
        ],
    )

    def _emit(msg: str) -> None:
        log.info(msg)
        if log_callback:
            log_callback(msg)

    subscription_url = env.get("SUBSCRIPTION_URL", "")
    if not subscription_url:
        log.error("SUBSCRIPTION_URL not set in %s", config_path)
        return 1

    kernel = env.get("PROXY_KERNEL", "singbox")
    nodes_file = env.get("NODES_FILE", "/etc/remnaproxy/nodes.json")
    state_file = env.get("STATE_FILE", "/etc/remnaproxy/state.json")

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
    )

    sm = StateManager(nodes_file, state_file)

    # 1. Ensure binaries and geo files
    if kernel == "xray":
        _emit("Checking xray binaries...")
        xray_bin = env.get("XRAY_BIN", "/usr/local/bin/xray")
        tun2socks_bin = env.get("TUN2SOCKS_BIN", "/usr/local/bin/tun2socks")
        xray_dir = env.get("XRAY_GEO_DIR", "/etc/xray")
        ensure_xray(xray_bin)
        ensure_tun2socks(tun2socks_bin)
        ensure_xray_rule_sets(xray_dir)
    else:
        _emit("Checking sing-box binaries...")
        sing_box_bin = env.get("SINGBOX_BIN", env.get("XRAY_BIN", "/usr/local/bin/sing-box"))
        rule_set_dir = env.get("RULE_SET_DIR", "/etc/sing-box")
        if not os.path.isfile(sing_box_bin) or not os.access(sing_box_bin, os.X_OK):
            log.error("sing-box binary not found: %s — run install.sh", sing_box_bin)
            return 1
        ensure_rule_sets(rule_set_dir, settings.geo_direct_ip, settings.geo_direct_site)

    # 2. Fetch subscription
    try:
        nodes = fetch_subscription(subscription_url)
        _emit(f"Fetched {len(nodes)} nodes from subscription")
    except ConnectionError as exc:
        log.warning("Subscription fetch failed: %s — using cached nodes", exc)
        nodes = sm.load_nodes()
        if not nodes:
            log.error("No cached nodes available")
            return 1

    if not nodes:
        log.error("Subscription returned 0 nodes")
        return 1

    # 3. Update nodes cache
    old_nodes = sm.load_nodes()
    sm.save_nodes(nodes)
    if len(nodes) != len(old_nodes):
        sm.set_current_index(0)
        log.info("Node list changed (%d → %d), reset to node 0", len(old_nodes), len(nodes))

    # 4. Generate config for current node
    current_node = sm.get_current_node()
    if current_node is None:
        log.error("No current node")
        return 1

    _emit(f"Generating {kernel} config for: {current_node.name} ({current_node.host}:{current_node.port})")

    if kernel == "xray":
        config_obj = generate_xray_config(current_node, settings)
        config_path_str = env.get("XRAY_CONFIG_FILE", "/etc/xray/xray-config.json")
    else:
        config_obj = generate_config(current_node, settings)
        config_path_str = env.get("XRAY_CONFIG", "/etc/sing-box/config.json")

    config_json = json.dumps(config_obj, indent=2)

    # 5. Write only if changed
    config_file = Path(config_path_str)
    config_file.parent.mkdir(parents=True, exist_ok=True)
    old_hash = _hash_file(config_path_str)
    new_hash = hashlib.sha256(config_json.encode()).hexdigest()
    if old_hash == new_hash:
        log.info("Config unchanged, no restart needed")
        return 0

    config_file.write_text(config_json)
    _emit(f"Config written to {config_path_str}")
    return 0


def _hash_file(path: str) -> str:
    try:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    except FileNotFoundError:
        return ""


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="/etc/remnaproxy/config.env")
    args = parser.parse_args()
    sys.exit(main(args.config))
