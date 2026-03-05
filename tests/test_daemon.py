import pytest
import threading
import time
from unittest.mock import patch, MagicMock, call
from src.daemon import Daemon, parse_interval


class TestParseInterval:
    def test_minutes(self):
        assert parse_interval("10min") == 600

    def test_seconds(self):
        assert parse_interval("30s") == 30

    def test_bare_number(self):
        assert parse_interval("120") == 120

    def test_whitespace(self):
        assert parse_interval("  5min  ") == 300


class TestDaemon:
    def _make_daemon(self, tmp_path):
        config = tmp_path / "config.env"
        config.write_text(
            "SUBSCRIPTION_URL=https://example.com/sub/TOKEN\n"
            "SYNC_INTERVAL=10min\n"
            "HEARTBEAT_INTERVAL=30s\n"
            "TUN_INTERFACE=tun0\n"
            "TUN_ADDRESS=172.19.0.1/30\n"
            "XRAY_BIN=/usr/local/bin/sing-box\n"
            "XRAY_CONFIG=/etc/sing-box/config.json\n"
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

    def test_sing_box_restart_on_exit(self, tmp_path):
        d = self._make_daemon(tmp_path)
        restart_count = []

        def fake_popen(cmd, **kwargs):
            proc = MagicMock()
            proc.wait.return_value = 1  # non-zero exit
            restart_count.append(1)
            if len(restart_count) >= 2:
                d._stop.set()  # stop after 2 restarts
            return proc

        with patch("subprocess.Popen", side_effect=fake_popen):
            with patch("time.sleep"):
                d._run_sing_box()

        assert len(restart_count) >= 1

    def test_loop_calls_fn_periodically(self, tmp_path):
        d = self._make_daemon(tmp_path)
        calls = []

        def fake_fn(config_path):
            calls.append(1)
            if len(calls) >= 2:
                d._stop.set()

        with patch("time.sleep"):
            d._loop(fake_fn, 1, "test")

        assert len(calls) >= 2
