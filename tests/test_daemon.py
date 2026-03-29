import pytest
import socket
import threading
import time
from pathlib import Path
from unittest.mock import patch, MagicMock, call

from src.daemon import (
    Daemon, SingboxRunner, XrayRunner, make_runner,
    parse_interval, _write_proxy_kernel,
    MAX_RESTARTS, RESTART_WINDOW,
)


# ── parse_interval ─────────────────────────────────────────────────────────────

class TestParseInterval:
    def test_minutes(self):
        assert parse_interval("10min") == 600

    def test_seconds(self):
        assert parse_interval("30s") == 30

    def test_bare_number(self):
        assert parse_interval("120") == 120

    def test_whitespace(self):
        assert parse_interval("  5min  ") == 300


# ── Daemon ─────────────────────────────────────────────────────────────────────

class TestDaemon:
    def _make_daemon(self, tmp_path, extra: str = "") -> Daemon:
        config = tmp_path / "config.env"
        config.write_text(
            "SUBSCRIPTION_URL=https://example.com/sub/TOKEN\n"
            "SYNC_INTERVAL=10min\n"
            "HEARTBEAT_INTERVAL=30s\n"
            "TUN_INTERFACE=tun0\n"
            "TUN_ADDRESS=172.19.0.1/30\n"
            "XRAY_BIN=/usr/local/bin/sing-box\n"
            "XRAY_CONFIG=/etc/sing-box/config.json\n"
            + extra
        )
        return Daemon(str(config))

    def test_init_loads_config(self, tmp_path):
        d = self._make_daemon(tmp_path)
        assert d.env["SUBSCRIPTION_URL"] == "https://example.com/sub/TOKEN"
        assert d.sync_interval == 600
        assert d.heartbeat_interval == 30

    def test_stop_sets_event(self, tmp_path):
        d = self._make_daemon(tmp_path)
        assert not d._stop.is_set()
        d.stop()
        assert d._stop.is_set()

    def test_setup_tun_calls_ip_commands(self, tmp_path):
        d = self._make_daemon(tmp_path)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            d.setup_tun()
        calls = [str(c) for c in mock_run.call_args_list]
        assert any("tuntap" in c for c in calls)
        assert any("addr" in c for c in calls)
        assert any("link" in c for c in calls)

    def test_selects_singbox_runner_by_default(self, tmp_path):
        d = self._make_daemon(tmp_path)
        runner = make_runner(d.env.get("PROXY_KERNEL", "singbox"), d.env)
        assert isinstance(runner, SingboxRunner)

    def test_selects_singbox_runner_when_explicit(self, tmp_path):
        d = self._make_daemon(tmp_path, extra="PROXY_KERNEL=singbox\n")
        runner = make_runner(d.env.get("PROXY_KERNEL", "singbox"), d.env)
        assert isinstance(runner, SingboxRunner)

    def test_selects_xray_runner_when_set(self, tmp_path):
        d = self._make_daemon(tmp_path, extra="PROXY_KERNEL=xray\n")
        runner = make_runner(d.env.get("PROXY_KERNEL", "singbox"), d.env)
        assert isinstance(runner, XrayRunner)

    def test_loop_calls_fn_periodically(self, tmp_path):
        d = self._make_daemon(tmp_path)
        calls = []

        def fake_fn(config_path):
            calls.append(1)
            if len(calls) >= 2:
                d._stop.set()

        d._loop(fake_fn, 0, "test")
        assert len(calls) >= 2


class TestWriteProxyKernel:
    def test_updates_existing_key(self, tmp_path):
        cfg = tmp_path / "config.env"
        cfg.write_text("PROXY_KERNEL=singbox\nFOO=bar\n")
        _write_proxy_kernel(str(cfg), "xray")
        text = cfg.read_text()
        assert "PROXY_KERNEL=xray" in text
        assert "PROXY_KERNEL=singbox" not in text
        assert "FOO=bar" in text

    def test_appends_when_absent(self, tmp_path):
        cfg = tmp_path / "config.env"
        cfg.write_text("FOO=bar\n")
        _write_proxy_kernel(str(cfg), "xray")
        assert "PROXY_KERNEL=xray" in cfg.read_text()


# ── SingboxRunner ──────────────────────────────────────────────────────────────

class TestSingboxRunner:
    def _make_proc(self, exit_code: int = 0) -> MagicMock:
        proc = MagicMock()
        proc.poll.return_value = None
        proc.wait.return_value = exit_code
        return proc

    def test_stop_is_non_raising_when_proc_is_none(self):
        r = SingboxRunner("/bin/sing-box", "/etc/sing-box/config.json")
        r.stop()  # must not raise

    def test_stop_is_non_raising_when_proc_already_dead(self):
        r = SingboxRunner("/bin/sing-box", "/etc/sing-box/config.json")
        proc = MagicMock()
        proc.poll.return_value = 0  # already exited
        r._proc = proc
        r.stop()  # must not raise

    def test_stop_sends_sigterm_then_sigkill_on_timeout(self):
        r = SingboxRunner("/bin/sing-box", "/etc/sing-box/config.json")
        proc = MagicMock()
        proc.poll.return_value = None
        proc.wait.side_effect = [None.__class__, None]
        import subprocess
        proc.wait.side_effect = [subprocess.TimeoutExpired(cmd="x", timeout=5), None]
        r._proc = proc
        r.stop()
        proc.terminate.assert_called_once()
        proc.kill.assert_called_once()

    def test_sliding_window_marks_failed_at_fifth_crash(self):
        r = SingboxRunner("/bin/sing-box", "/etc/sing-box/config.json")
        for _ in range(MAX_RESTARTS - 1):
            r._record_crash()
            assert not r.failed()
        r._record_crash()
        assert r.failed()

    def test_sliding_window_does_not_fail_when_crashes_spread_over_window(self):
        r = SingboxRunner("/bin/sing-box", "/etc/sing-box/config.json")
        now = time.monotonic()
        # Inject old timestamps outside the window
        r._crash_times = [now - RESTART_WINDOW - 10] * (MAX_RESTARTS - 1)
        r._record_crash()
        assert not r.failed()

    def test_log_path_is_string(self):
        r = SingboxRunner("/bin/sing-box", "/etc/sing-box/config.json")
        assert isinstance(r.log_path, str)
        assert len(r.log_path) > 0


# ── XrayRunner ─────────────────────────────────────────────────────────────────

class TestXrayRunner:
    def _make_runner(self) -> XrayRunner:
        return XrayRunner(
            xray_binary="/usr/local/bin/xray",
            xray_config="/etc/xray/xray-config.json",
            tun2socks_binary="/usr/local/bin/tun2socks",
        )

    def test_stop_is_non_raising_when_procs_are_none(self):
        r = self._make_runner()
        r.stop()  # must not raise

    def test_stop_is_non_raising_when_procs_already_dead(self):
        r = self._make_runner()
        for attr in ("_xray_proc", "_tun2socks_proc"):
            proc = MagicMock()
            proc.poll.return_value = 0
            setattr(r, attr, proc)
        r.stop()  # must not raise

    def test_stop_kills_both_procs(self):
        r = self._make_runner()
        procs = []
        for attr in ("_xray_proc", "_tun2socks_proc"):
            proc = MagicMock()
            proc.poll.return_value = None
            proc.wait.return_value = None
            setattr(r, attr, proc)
            procs.append(proc)
        r.stop()
        for proc in procs:
            proc.terminate.assert_called_once()

    def test_log_path_is_string(self):
        r = self._make_runner()
        assert isinstance(r.log_path, str)
        assert len(r.log_path) > 0

    def test_sliding_window_marks_failed_at_fifth_crash(self):
        r = self._make_runner()
        r._stop_event.set()  # prevent restart attempts
        for _ in range(MAX_RESTARTS - 1):
            r._crash_times.append(time.monotonic())
            assert not r.failed()
        r._on_crash()
        assert r.failed()

    def test_sliding_window_allows_recovery_after_window(self):
        r = self._make_runner()
        now = time.monotonic()
        r._crash_times = [now - RESTART_WINDOW - 10] * (MAX_RESTARTS - 1)
        with patch.object(r, "stop"), patch.object(r, "start"):
            r._on_crash()
        assert not r.failed()

    def test_start_raises_if_socks5_not_ready(self, tmp_path):
        r = self._make_runner()
        r.PROBE_TIMEOUT = 0.1
        r.PROBE_INTERVAL = 0.05
        log_file = tmp_path / "xray.log"

        fake_proc = MagicMock()
        fake_proc.poll.return_value = None
        fake_proc.wait.return_value = 0

        with patch("subprocess.Popen", return_value=fake_proc):
            with patch("builtins.open", return_value=MagicMock(
                __enter__=lambda s, *a: s, __exit__=lambda s, *a: None
            )):
                with patch("socket.create_connection", side_effect=OSError("refused")):
                    with pytest.raises(RuntimeError, match="SOCKS5 not ready"):
                        r.start()


# ── restart_kernel ─────────────────────────────────────────────────────────────

class TestRestartKernel:
    def _make_daemon(self, tmp_path, kernel: str = "singbox") -> Daemon:
        cfg = tmp_path / "config.env"
        cfg.write_text(
            f"PROXY_KERNEL={kernel}\n"
            "SUBSCRIPTION_URL=https://example.com/sub/TOKEN\n"
            "SYNC_INTERVAL=10min\n"
            "HEARTBEAT_INTERVAL=30s\n"
        )
        return Daemon(str(cfg))

    def test_no_op_when_same_kernel(self, tmp_path):
        d = self._make_daemon(tmp_path, kernel="singbox")
        old_runner = MagicMock()
        d._runner = old_runner
        with patch("src.daemon.sync_main"):
            d.restart_kernel("singbox")
        old_runner.stop.assert_not_called()

    def test_switches_kernel_and_updates_config_env(self, tmp_path):
        d = self._make_daemon(tmp_path, kernel="singbox")
        old_runner = MagicMock()
        d._runner = old_runner

        new_runner = MagicMock()
        new_runner.failed.return_value = False

        with patch("src.daemon.sync_main"):
            with patch("src.daemon.make_runner", return_value=new_runner) as mock_make:
                d.restart_kernel("xray")

        old_runner.stop.assert_called_once()
        new_runner.start.assert_called_once()
        assert d._runner is new_runner
        cfg_text = Path(d.config_path).read_text()
        assert "PROXY_KERNEL=xray" in cfg_text

    def test_reverts_config_env_on_sync_failure(self, tmp_path):
        d = self._make_daemon(tmp_path, kernel="singbox")
        old_runner = MagicMock()
        d._runner = old_runner

        with patch("src.daemon.sync_main", side_effect=RuntimeError("sync failed")):
            with patch("src.daemon.make_runner", return_value=MagicMock()) as mock_make:
                with pytest.raises(RuntimeError):
                    d.restart_kernel("xray")

        cfg_text = Path(d.config_path).read_text()
        assert "PROXY_KERNEL=singbox" in cfg_text

    def test_reverts_and_restarts_old_runner_on_failure(self, tmp_path):
        d = self._make_daemon(tmp_path, kernel="singbox")
        old_runner = MagicMock()
        d._runner = old_runner

        reverted_runner = MagicMock()

        def make_runner_side_effect(kernel, env):
            if kernel == "singbox":
                return reverted_runner
            raise RuntimeError("start failed")

        with patch("src.daemon.sync_main"):
            with patch("src.daemon.make_runner", side_effect=make_runner_side_effect):
                with pytest.raises(RuntimeError):
                    d.restart_kernel("xray")

        reverted_runner.start.assert_called_once()
        assert d._runner is reverted_runner

    def test_log_callback_receives_messages(self, tmp_path):
        d = self._make_daemon(tmp_path, kernel="singbox")
        d._runner = MagicMock()
        messages = []

        with patch("src.daemon.sync_main"):
            with patch("src.daemon.make_runner", return_value=MagicMock()):
                d.restart_kernel("xray", log_callback=messages.append)

        assert any("xray" in m.lower() or "switch" in m.lower() for m in messages)
