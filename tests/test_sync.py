"""Tests for sync.py — config validation, load_env, parse_interval."""
import pytest
from pathlib import Path
from src.sync import (
    load_env,
    parse_interval,
    validate_and_fix_config,
    _is_valid_interval,
    _is_valid_cidr,
)


class TestLoadEnv:
    def test_reads_key_value(self, tmp_path):
        cfg = tmp_path / "config.env"
        cfg.write_text("FOO=bar\nBAZ=qux\n")
        env = load_env(str(cfg))
        assert env["FOO"] == "bar"
        assert env["BAZ"] == "qux"

    def test_skips_comments_and_blanks(self, tmp_path):
        cfg = tmp_path / "config.env"
        cfg.write_text("# comment\n\nKEY=val\n")
        env = load_env(str(cfg))
        assert list(env.keys()) == ["KEY"]

    def test_missing_file_returns_empty(self, tmp_path):
        env = load_env(str(tmp_path / "nonexistent.env"))
        assert env == {}

    def test_value_with_equals(self, tmp_path):
        cfg = tmp_path / "config.env"
        cfg.write_text("URL=https://example.com/sub?token=abc=def\n")
        env = load_env(str(cfg))
        assert env["URL"] == "https://example.com/sub?token=abc=def"


class TestParseInterval:
    def test_minutes(self):     assert parse_interval("10min") == 600
    def test_seconds(self):     assert parse_interval("30s") == 30
    def test_bare_int(self):    assert parse_interval("120") == 120
    def test_whitespace(self):  assert parse_interval("  5min  ") == 300

    def test_invalid_raises(self):
        with pytest.raises((ValueError, AttributeError)):
            parse_interval("bad")


class TestValidators:
    def test_valid_intervals(self):
        assert _is_valid_interval("10min")
        assert _is_valid_interval("30s")
        assert _is_valid_interval("60")

    def test_invalid_intervals(self):
        assert not _is_valid_interval("bad")
        assert not _is_valid_interval("")
        assert not _is_valid_interval("notanumber")

    def test_valid_cidr(self):
        assert _is_valid_cidr("172.19.0.1/30")
        assert _is_valid_cidr("10.0.0.1/8")

    def test_invalid_cidr(self):
        assert not _is_valid_cidr("notanip")
        assert not _is_valid_cidr("999.0.0.1/24")


class TestValidateAndFixConfig:
    def _make_config(self, tmp_path, content: str) -> str:
        cfg = tmp_path / "config.env"
        cfg.write_text(content)
        return str(cfg)

    def test_valid_config_unchanged(self, tmp_path):
        path = self._make_config(tmp_path,
            "SUBSCRIPTION_URL=https://example.com/sub/TOKEN\n"
            "SYNC_INTERVAL=10min\n"
            "HEARTBEAT_INTERVAL=30s\n"
            "TUN_ADDRESS=172.19.0.1/30\n"
        )
        env = validate_and_fix_config(path)
        assert env["SUBSCRIPTION_URL"] == "https://example.com/sub/TOKEN"
        assert env["SYNC_INTERVAL"] == "10min"

    def test_invalid_interval_is_fixed(self, tmp_path):
        path = self._make_config(tmp_path,
            "SUBSCRIPTION_URL=https://example.com/sub/TOKEN\n"
            "SYNC_INTERVAL=bad_value\n"
        )
        env = validate_and_fix_config(path)
        assert env["SYNC_INTERVAL"] == "10min"
        # Check it was written back to file
        written = load_env(path)
        assert written["SYNC_INTERVAL"] == "10min"

    def test_invalid_cidr_is_fixed(self, tmp_path):
        path = self._make_config(tmp_path,
            "SUBSCRIPTION_URL=https://example.com/sub/TOKEN\n"
            "TUN_ADDRESS=not_a_cidr\n"
        )
        env = validate_and_fix_config(path)
        assert env["TUN_ADDRESS"] == "172.19.0.1/30"

    def test_invalid_tun_stack_is_fixed(self, tmp_path):
        path = self._make_config(tmp_path,
            "SUBSCRIPTION_URL=https://example.com/sub/TOKEN\n"
            "TUN_STACK=xray\n"
        )
        env = validate_and_fix_config(path)
        assert env["TUN_STACK"] == "mixed"

    def test_invalid_multiplex_protocol_is_cleared(self, tmp_path):
        path = self._make_config(tmp_path,
            "SUBSCRIPTION_URL=https://example.com/sub/TOKEN\n"
            "MULTIPLEX_PROTOCOL=badproto\n"
        )
        env = validate_and_fix_config(path)
        assert env["MULTIPLEX_PROTOCOL"] == ""

    def test_valid_multiplex_protocol_kept(self, tmp_path):
        path = self._make_config(tmp_path,
            "SUBSCRIPTION_URL=https://example.com/sub/TOKEN\n"
            "MULTIPLEX_PROTOCOL=h2mux\n"
        )
        env = validate_and_fix_config(path)
        assert env["MULTIPLEX_PROTOCOL"] == "h2mux"

    def test_missing_optional_keys_get_defaults(self, tmp_path):
        path = self._make_config(tmp_path,
            "SUBSCRIPTION_URL=https://example.com/sub/TOKEN\n"
        )
        env = validate_and_fix_config(path)
        assert env["SYNC_INTERVAL"] == "10min"
        assert env["TUN_INTERFACE"] == "tun0"
        assert env["TUN_STACK"] == "mixed"
        assert env["XRAY_BIN"] == "/usr/local/bin/sing-box"

    def test_missing_file_creates_defaults(self, tmp_path):
        path = str(tmp_path / "config.env")
        # File doesn't exist yet
        env = validate_and_fix_config(path)
        assert "SYNC_INTERVAL" in env
        assert env["SYNC_INTERVAL"] == "10min"

    def test_invalid_fail_threshold_is_fixed(self, tmp_path):
        path = self._make_config(tmp_path,
            "SUBSCRIPTION_URL=https://example.com/sub/TOKEN\n"
            "HEARTBEAT_FAIL_THRESHOLD=0\n"
        )
        env = validate_and_fix_config(path)
        assert env["HEARTBEAT_FAIL_THRESHOLD"] == "2"

    def test_comments_preserved_after_fix(self, tmp_path):
        path = self._make_config(tmp_path,
            "# My config\n"
            "SUBSCRIPTION_URL=https://example.com/sub/TOKEN\n"
            "SYNC_INTERVAL=bad\n"
        )
        validate_and_fix_config(path)
        raw = Path(path).read_text()
        assert "# My config" in raw
        assert "SYNC_INTERVAL=10min" in raw

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
