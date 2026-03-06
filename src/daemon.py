#!/usr/bin/env python3
"""
Container PID 1 supervisor — manages sing-box + sync + heartbeat.

Usage:
  python3 daemon.py [--config /etc/remnaproxy/config.env]
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

log = logging.getLogger("remnaproxy-daemon")

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
        log.info("Starting remnaproxy daemon")

        # Remove stale config so sync always generates a fresh one on startup
        config_file = Path(self.env.get("XRAY_CONFIG", "/etc/sing-box/config.json"))
        if config_file.exists():
            config_file.unlink()
            log.info("Removed stale config %s", config_file)

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


def main(config_path: str = "/etc/remnaproxy/config.env") -> int:
    log_dir = load_env(config_path).get("LOG_DIR", "/var/log/remnaproxy")
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
    parser.add_argument("--config", default="/etc/remnaproxy/config.env")
    args = parser.parse_args()
    sys.exit(main(args.config))
