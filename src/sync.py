#!/usr/bin/env python3
"""
remnawave-sync — fetch subscription and update sing-box config.

Usage:
  python3 sync.py [--config /etc/remnawave/config.env]
"""
from __future__ import annotations
import argparse
import hashlib
import json
import logging
import os
import subprocess
import sys
from pathlib import Path

# Allow running directly as script
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.binary_manager import ensure_sing_box, ensure_geo_files
from src.config_generator import ConfigSettings, generate_config
from src.state_manager import StateManager
from src.subscription import fetch_subscription

log = logging.getLogger("remnawave-sync")


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


def main(config_path: str = "/etc/remnawave/config.env") -> int:
    env = load_env(config_path)
    env = {**os.environ, **env}  # env file takes precedence

    log_dir = env.get("LOG_DIR", "/var/log/remnawave")
    Path(log_dir).mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[
            logging.FileHandler(f"{log_dir}/sync.log"),
            logging.StreamHandler(),
        ],
    )

    subscription_url = env.get("SUBSCRIPTION_URL", "")
    if not subscription_url:
        log.error("SUBSCRIPTION_URL not set in %s", config_path)
        return 1

    sing_box_bin  = env.get("XRAY_BIN", "/usr/local/bin/sing-box")
    xray_config   = env.get("XRAY_CONFIG", "/etc/sing-box/config.json")
    nodes_file    = env.get("NODES_FILE", "/etc/remnawave/nodes.json")
    state_file    = env.get("STATE_FILE", "/etc/remnawave/state.json")
    geoip_path    = env.get("GEOIP_PATH", "/etc/sing-box/geoip.db")
    geosite_path  = env.get("GEOSITE_PATH", "/etc/sing-box/geosite.db")

    settings = ConfigSettings(
        tun_interface=env.get("TUN_INTERFACE", "tun0"),
        tun_address=env.get("TUN_ADDRESS", "172.19.0.1/30"),
        geo_direct_ip=env.get("GEO_DIRECT_IP", "private,ru").split(","),
        geo_direct_site=env.get("GEO_DIRECT_SITE", "ru").split(","),
        geoip_path=geoip_path,
        geosite_path=geosite_path,
    )

    sm = StateManager(nodes_file, state_file)

    # 1. Ensure binaries/geo files are present
    try:
        ensure_sing_box(sing_box_bin)
        ensure_geo_files(geoip_path, geosite_path)
    except Exception as exc:
        log.error("Binary setup failed: %s", exc)
        return 1

    # 2. Fetch subscription
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

    # 3. Update nodes cache (reset index if node count changed)
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

    log.info("Generating config for node: %s (%s:%d)", current_node.name, current_node.host, current_node.port)
    config = generate_config(current_node, settings)
    config_json = json.dumps(config, indent=2)

    # 5. Compare with existing config — only restart if changed
    config_path_obj = Path(xray_config)
    config_path_obj.parent.mkdir(parents=True, exist_ok=True)

    old_hash = _hash_file(xray_config)
    new_hash = hashlib.sha256(config_json.encode()).hexdigest()

    if old_hash == new_hash:
        log.info("Config unchanged, no restart needed")
        return 0

    config_path_obj.write_text(config_json)
    log.info("Config written to %s", xray_config)

    # 6. Reload/start sing-box
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
    parser.add_argument("--config", default="/etc/remnawave/config.env")
    args = parser.parse_args()
    sys.exit(main(args.config))
