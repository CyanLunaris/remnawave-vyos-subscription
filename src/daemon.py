#!/usr/bin/env python3
"""
Container PID 1 supervisor — manages proxy kernel + sync + heartbeat.

Usage:
  python3 daemon.py [--config /etc/remnaproxy/config.env]
"""
from __future__ import annotations
import argparse
import logging
import signal
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Callable, List, Optional

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.sync import main as sync_main, load_env
from src.heartbeat import main as heartbeat_main

log = logging.getLogger("remnaproxy-daemon")

MAX_RESTARTS = 5
RESTART_WINDOW = 60  # seconds
STOP_TIMEOUT = 5     # seconds before SIGKILL


def parse_interval(s: str) -> int:
    """Parse '10min', '30s', or bare seconds string to int seconds."""
    s = s.strip()
    if s.endswith("min"):
        return int(s[:-3]) * 60
    if s.endswith("s"):
        return int(s[:-1])
    return int(s)


# ── Runner base contract ───────────────────────────────────────────────────────

class _BaseRunner:
    log_path: str = ""

    def start(self) -> None:
        raise NotImplementedError

    def stop(self) -> None:
        raise NotImplementedError

    def failed(self) -> bool:
        raise NotImplementedError


# ── SingboxRunner ──────────────────────────────────────────────────────────────

class SingboxRunner(_BaseRunner):
    def __init__(self, binary: str, config: str):
        self._binary = binary
        self._config = config
        self.log_path = "/var/log/remnaproxy/sing-box.log"
        self._proc: Optional[subprocess.Popen] = None
        self._crash_times: List[float] = []
        self._failed = False
        self._stop_event = threading.Event()
        self._watch_thread: Optional[threading.Thread] = None

    def start(self) -> None:
        self._stop_event.clear()
        self._proc = subprocess.Popen([self._binary, "run", "-c", self._config])
        self._watch_thread = threading.Thread(target=self._watch, daemon=True, name="singbox-watch")
        self._watch_thread.start()
        log.info("SingboxRunner started")

    def stop(self) -> None:
        self._stop_event.set()
        try:
            if self._proc and self._proc.poll() is None:
                self._proc.terminate()
                try:
                    self._proc.wait(timeout=STOP_TIMEOUT)
                except subprocess.TimeoutExpired:
                    self._proc.kill()
                    self._proc.wait()
        except Exception:
            pass

    def failed(self) -> bool:
        return self._failed

    def _watch(self) -> None:
        while not self._stop_event.is_set():
            if self._proc is None:
                break
            ret = self._proc.wait()
            if self._stop_event.is_set():
                break
            log.warning("sing-box exited (code %d)", ret)
            self._record_crash()
            if self._failed:
                log.error("sing-box restart limit reached")
                break
            log.info("Restarting sing-box...")
            self._proc = subprocess.Popen([self._binary, "run", "-c", self._config])

    def _record_crash(self) -> None:
        now = time.monotonic()
        self._crash_times.append(now)
        self._crash_times = [t for t in self._crash_times if now - t <= RESTART_WINDOW]
        if len(self._crash_times) >= MAX_RESTARTS:
            self._failed = True


# ── XrayRunner ─────────────────────────────────────────────────────────────────

class XrayRunner(_BaseRunner):
    SOCKS5_HOST = "127.0.0.1"
    SOCKS5_PORT = 7891
    PROBE_INTERVAL = 0.2   # seconds
    PROBE_TIMEOUT = 10.0   # seconds

    def __init__(self, xray_binary: str, xray_config: str,
                 tun2socks_binary: str, tun_device: str = "tun0"):
        self._xray_bin = xray_binary
        self._xray_config = xray_config
        self._tun2socks_bin = tun2socks_binary
        self._tun_device = tun_device
        self.log_path = "/var/log/remnaproxy/xray-error.log"
        self._xray_proc: Optional[subprocess.Popen] = None
        self._tun2socks_proc: Optional[subprocess.Popen] = None
        self._crash_times: List[float] = []
        self._failed = False
        self._stop_event = threading.Event()

    def start(self) -> None:
        self._stop_event.clear()
        log_file = open(self.log_path, "ab")

        # 1. Start xray
        xray_env = {"XRAY_LOCATION_ASSET": "/etc/xray/"}
        import os
        env = {**os.environ, **xray_env}
        self._xray_proc = subprocess.Popen(
            [self._xray_bin, "run", "-c", self._xray_config],
            stderr=log_file,
            env=env,
        )

        # 2. TCP probe on SOCKS5 port
        deadline = time.monotonic() + self.PROBE_TIMEOUT
        while True:
            try:
                with socket.create_connection(
                    (self.SOCKS5_HOST, self.SOCKS5_PORT), timeout=self.PROBE_INTERVAL
                ):
                    break
            except OSError:
                if time.monotonic() >= deadline:
                    self.stop()
                    raise RuntimeError(
                        f"xray SOCKS5 not ready at {self.SOCKS5_HOST}:{self.SOCKS5_PORT} "
                        f"after {self.PROBE_TIMEOUT}s"
                    )
                time.sleep(self.PROBE_INTERVAL)

        # 3. Start tun2socks
        self._tun2socks_proc = subprocess.Popen(
            [
                self._tun2socks_bin,
                "-device", f"tun://{self._tun_device}",
                "-proxy", f"socks5://{self.SOCKS5_HOST}:{self.SOCKS5_PORT}",
                "-loglevel", "warning",
            ],
            stderr=log_file,
        )

        # 4. Start watch threads for both subprocesses
        threading.Thread(
            target=self._watch_proc, args=(self._xray_proc, "xray"),
            daemon=True, name="xray-watch",
        ).start()
        threading.Thread(
            target=self._watch_proc, args=(self._tun2socks_proc, "tun2socks"),
            daemon=True, name="tun2socks-watch",
        ).start()

        log.info("XrayRunner started")

    def stop(self) -> None:
        self._stop_event.set()
        for proc in (self._tun2socks_proc, self._xray_proc):
            if proc is None:
                continue
            try:
                if proc.poll() is None:
                    proc.terminate()
                    try:
                        proc.wait(timeout=STOP_TIMEOUT)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait()
            except Exception:
                pass

    def failed(self) -> bool:
        return self._failed

    def _watch_proc(self, proc: subprocess.Popen, name: str) -> None:
        ret = proc.wait()
        if self._stop_event.is_set():
            return
        # Guard against stale watch threads after a restart replaced the process.
        if proc is not self._xray_proc and proc is not self._tun2socks_proc:
            return
        log.warning("%s exited unexpectedly (code %d)", name, ret)
        self._on_crash()

    def _on_crash(self) -> None:
        now = time.monotonic()
        self._crash_times.append(now)
        self._crash_times = [t for t in self._crash_times if now - t <= RESTART_WINDOW]
        if len(self._crash_times) >= MAX_RESTARTS:
            self._failed = True
            log.error("XrayRunner: restart limit reached — stopping")
            return
        log.info("XrayRunner: restarting both subprocesses...")
        self.stop()
        try:
            self.start()
        except Exception as exc:
            log.error("XrayRunner: restart failed: %s", exc)
            self._failed = True


# ── Runner factory ─────────────────────────────────────────────────────────────

def make_runner(kernel: str, env: dict) -> _BaseRunner:
    if kernel == "xray":
        return XrayRunner(
            xray_binary=env.get("XRAY_CORE_BIN", "/usr/local/bin/xray"),
            xray_config=env.get("XRAY_CONFIG_FILE", "/etc/xray/xray-config.json"),
            tun2socks_binary=env.get("TUN2SOCKS_BIN", "/usr/local/bin/tun2socks"),
            tun_device=env.get("TUN_INTERFACE", "tun0"),
        )
    return SingboxRunner(
        binary=env.get("SINGBOX_BIN", "/usr/local/bin/sing-box"),
        config=env.get("XRAY_CONFIG", "/etc/sing-box/config.json"),
    )


# ── Daemon ─────────────────────────────────────────────────────────────────────

class Daemon:
    def __init__(self, config_path: str):
        self.config_path = config_path
        self.env = load_env(config_path)
        self._stop = threading.Event()
        self._runner: Optional[_BaseRunner] = None
        self.sync_interval = parse_interval(self.env.get("SYNC_INTERVAL", "10min"))
        self.heartbeat_interval = parse_interval(self.env.get("HEARTBEAT_INTERVAL", "30s"))

    # ── Public interface ───────────────────────────────────────────────────────

    def start(self) -> None:
        log.info("Starting remnaproxy daemon")

        try:
            sync_main(self.config_path)
        except Exception as exc:
            log.error("Initial sync failed: %s", exc)

        self.setup_tun()

        kernel = self.env.get("PROXY_KERNEL", "singbox")
        self._runner = make_runner(kernel, self.env)
        self._runner.start()

        threading.Thread(
            target=self._loop, args=(sync_main, self.sync_interval, "sync"),
            daemon=True, name="sync-loop",
        ).start()
        threading.Thread(
            target=self._loop, args=(heartbeat_main, self.heartbeat_interval, "heartbeat"),
            daemon=True, name="heartbeat-loop",
        ).start()

    def stop(self) -> None:
        log.info("Stopping daemon")
        self._stop.set()
        if self._runner:
            self._runner.stop()

    def wait(self) -> None:
        try:
            while not self._stop.is_set():
                self._stop.wait(timeout=1)
        except KeyboardInterrupt:
            self.stop()

    def setup_tun(self) -> None:
        tun_if = self.env.get("TUN_INTERFACE", "tun0")
        tun_addr = self.env.get("TUN_ADDRESS", "172.19.0.1/30")
        cmds = [
            ["/sbin/ip", "tuntap", "add", "mode", "tun", tun_if],
            ["/sbin/ip", "addr", "add", tun_addr, "dev", tun_if],
            ["/sbin/ip", "link", "set", tun_if, "up"],
            # Larger TX queue reduces packet drops under bursty multi-device load.
            ["/sbin/ip", "link", "set", tun_if, "txqueuelen", "1000"],
        ]
        for cmd in cmds:
            result = subprocess.run(cmd, capture_output=True)
            if result.returncode != 0:
                log.debug("ip command %s: %s", cmd[2], result.stderr.decode().strip())

    def restart_kernel(self, new_kernel: str,
                       log_callback: Optional[Callable[[str], None]] = None) -> None:
        """Hot-switch proxy kernel. tun0 is preserved; brief packet loss is expected."""
        def _log(msg: str) -> None:
            log.info(msg)
            if log_callback:
                log_callback(msg)

        old_kernel = self.env.get("PROXY_KERNEL", "singbox")
        if old_kernel == new_kernel:
            return

        _log(f"Switching kernel: {old_kernel} → {new_kernel}")

        # 1. Write new kernel to config.env
        _write_proxy_kernel(self.config_path, new_kernel)
        self.env["PROXY_KERNEL"] = new_kernel

        try:
            # 2. Stop current runner (tun0 stays up)
            if self._runner:
                self._runner.stop()

            # 3. Sync: download binaries + generate config for new kernel
            _log("Running sync for new kernel...")
            sync_main(self.config_path, log_callback=log_callback)

            # 4. Start new runner
            _log(f"Starting {new_kernel} runner...")
            new_runner = make_runner(new_kernel, self.env)
            new_runner.start()
            self._runner = new_runner
            _log(f"Kernel switched to {new_kernel}")

        except Exception as exc:
            log.error("Kernel switch failed: %s — reverting to %s", exc, old_kernel)
            _write_proxy_kernel(self.config_path, old_kernel)
            self.env["PROXY_KERNEL"] = old_kernel
            try:
                old_runner = make_runner(old_kernel, self.env)
                old_runner.start()
                self._runner = old_runner
                _log(f"Reverted to {old_kernel}")
            except Exception as revert_exc:
                log.critical(
                    "Failed to restart old kernel %s after failed switch: %s",
                    old_kernel, revert_exc,
                )
                self._runner = None
            raise

    # ── Internal ──────────────────────────────────────────────────────────────

    def _loop(self, fn, interval: int, name: str) -> None:
        self._stop.wait(timeout=interval)
        while not self._stop.is_set():
            try:
                fn(self.config_path)
            except Exception as exc:
                log.error("%s loop error: %s", name, exc)
            self._stop.wait(timeout=interval)


def _write_proxy_kernel(config_path: str, kernel: str) -> None:
    """Update or append PROXY_KERNEL= in config.env."""
    p = Path(config_path)
    lines = p.read_text().splitlines() if p.exists() else []
    found = False
    new_lines = []
    for line in lines:
        if line.strip().startswith("PROXY_KERNEL="):
            new_lines.append(f"PROXY_KERNEL={kernel}")
            found = True
        else:
            new_lines.append(line)
    if not found:
        new_lines.append(f"PROXY_KERNEL={kernel}")
    p.write_text("\n".join(new_lines) + "\n")


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
