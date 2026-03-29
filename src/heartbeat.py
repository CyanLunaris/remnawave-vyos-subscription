#!/usr/bin/env python3
"""
remnaproxy-heartbeat — check connectivity and rotate nodes on failure.

Usage:
  python3 heartbeat.py [--config /etc/remnaproxy/config.env]
"""
from __future__ import annotations
import argparse
import json
import logging
import os
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.config_generator import ConfigSettings, generate_config
from src.xray_config_generator import generate_xray_config
from src.state_manager import StateManager

log = logging.getLogger("remnaproxy-heartbeat")


def check_connectivity(host: str, timeout: int = 5) -> bool:
    """Return True if we can reach the heartbeat host via HTTP."""
    url = f"https://{host}"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return resp.status < 400
    except Exception:
        return False


def run_heartbeat_check(
    sm: StateManager,
    fail_threshold: int,
    heartbeat_host: str,
    timeout: int,
    config_path: str = "/etc/remnaproxy/config.env",
    cooldown: int = 2,
) -> bool:
    """Run one heartbeat check. Returns True if node was switched."""
    # If we're in cooldown after a recent rotation, skip checks
    remaining = sm.get_cooldown()
    if remaining > 0:
        sm.decrement_cooldown()
        log.info("Post-rotation cooldown active (%d checks remaining), skipping", remaining)
        return False

    if check_connectivity(heartbeat_host, timeout):
        if sm.get_fail_count() > 0:
            log.info("Connectivity restored, resetting fail count")
        sm.reset_fail_count()
        sm.set_cooldown(0)
        return False

    count = sm.increment_fail_count()
    log.warning("Connectivity check failed (%d/%d)", count, fail_threshold)

    if count >= fail_threshold:
        old_idx = sm.get_current_index()
        new_idx = sm.rotate_node()
        sm.reset_fail_count()
        sm.set_cooldown(cooldown)
        node = sm.get_current_node()
        node_name = node.name if node else "unknown"
        log.warning("Switching node %d → %d (%s)", old_idx, new_idx, node_name)
        _apply_new_node(sm, config_path)
        return True

    return False


def _apply_new_node(sm: StateManager, config_path: str = "/etc/remnaproxy/config.env") -> None:
    """Regenerate config for new current node and reload proxy kernel."""
    from src.sync import load_env
    env = load_env(config_path)
    env = {**os.environ, **env}

    node = sm.get_current_node()
    if node is None:
        log.error("No node available after rotation")
        return

    kernel = env.get("PROXY_KERNEL", "singbox")
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
    )

    if kernel == "xray":
        config = generate_xray_config(node, settings)
        config_file = env.get("XRAY_CONFIG_FILE", "/etc/xray/xray-config.json")
    else:
        config = generate_config(node, settings)
        config_file = env.get("XRAY_CONFIG", "/etc/sing-box/config.json")

    try:
        Path(config_file).write_text(json.dumps(config, indent=2))
        log.info("Config updated for node: %s", node.name)
    except OSError as exc:
        log.error("Failed to write config: %s", exc)
        return
    _reload_proxy(kernel)


def _reload_proxy(kernel: str) -> None:
    from src.tui_helpers import reload_proxy
    if reload_proxy(kernel):
        log.info("%s reloaded", kernel)
    else:
        log.error("%s reload failed", kernel)


def main(config_path: str = "/etc/remnaproxy/config.env") -> int:
    from src.sync import load_env
    env = load_env(config_path)
    env = {**os.environ, **env}

    log_dir = env.get("LOG_DIR", "/var/log/remnaproxy")
    Path(log_dir).mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[
            logging.FileHandler(f"{log_dir}/heartbeat.log"),
            logging.StreamHandler(),
        ],
    )

    sm = StateManager(
        env.get("NODES_FILE", "/etc/remnaproxy/nodes.json"),
        env.get("STATE_FILE", "/etc/remnaproxy/state.json"),
    )

    run_heartbeat_check(
        sm,
        fail_threshold=int(env.get("HEARTBEAT_FAIL_THRESHOLD", "2")),
        heartbeat_host=env.get("HEARTBEAT_HOST", "cp.cloudflare.com"),
        timeout=int(env.get("HEARTBEAT_TIMEOUT", "5")),
        config_path=config_path,
        cooldown=int(env.get("HEARTBEAT_COOLDOWN", "2")),
    )
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="/etc/remnaproxy/config.env")
    args = parser.parse_args()
    sys.exit(main(args.config))
