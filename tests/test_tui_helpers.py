import shutil
import tempfile
import pytest
from pathlib import Path
from src.tui_helpers import (
    get_status,
    read_config,
    write_config,
    get_last_log_line,
    detect_reload_mode,
)
from src.uri_parser import ParsedNode
from src.state_manager import StateManager


def make_node(name: str, protocol: str = "vless") -> ParsedNode:
    return ParsedNode(
        protocol=protocol, host=f"{name}.example.com", port=443,
        name=name, uuid="uuid", security="reality",
        reality_pbk="KEY", reality_sid="sid",
    )


class TestGetStatus:
    def setup_method(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.nodes_file = self.tmp / "nodes.json"
        self.state_file = self.tmp / "state.json"

    def teardown_method(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _make_sm(self, nodes, index=0):
        sm = StateManager(str(self.nodes_file), str(self.state_file))
        sm.save_nodes(nodes)
        sm.set_current_index(index)
        return sm

    def test_current_node_name(self):
        self._make_sm([make_node("NL-1"), make_node("DE-1")], index=0)
        status = get_status(str(self.nodes_file), str(self.state_file))
        assert status["current_node_name"] == "NL-1"

    def test_current_node_index(self):
        self._make_sm([make_node("A"), make_node("B")], index=1)
        status = get_status(str(self.nodes_file), str(self.state_file))
        assert status["current_index"] == 1

    def test_node_count(self):
        self._make_sm([make_node("A"), make_node("B"), make_node("C")])
        status = get_status(str(self.nodes_file), str(self.state_file))
        assert status["node_count"] == 3

    def test_fail_count(self):
        sm = self._make_sm([make_node("A")])
        sm.increment_fail_count()
        sm.increment_fail_count()
        status = get_status(str(self.nodes_file), str(self.state_file))
        assert status["fail_count"] == 2

    def test_no_nodes_returns_defaults(self):
        status = get_status(str(self.nodes_file), str(self.state_file))
        assert status["current_node_name"] == "N/A"
        assert status["node_count"] == 0

    def test_protocol_label(self):
        sm = self._make_sm([make_node("NL-1", protocol="trojan")])
        status = get_status(str(self.nodes_file), str(self.state_file))
        assert status["current_node_protocol"] == "trojan"


class TestReadWriteConfig:
    def setup_method(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.config = self.tmp / "config.env"
        self.config.write_text(
            "SUBSCRIPTION_URL=https://example.com/sub/TOKEN\n"
            "SYNC_INTERVAL=10min\n"
            "GEO_DIRECT_IP=private,ru\n"
            "# comment line\n"
        )

    def teardown_method(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_read_config_returns_dict(self):
        cfg = read_config(str(self.config))
        assert cfg["SUBSCRIPTION_URL"] == "https://example.com/sub/TOKEN"
        assert cfg["SYNC_INTERVAL"] == "10min"
        assert cfg["GEO_DIRECT_IP"] == "private,ru"

    def test_read_config_skips_comments(self):
        cfg = read_config(str(self.config))
        assert "# comment line" not in cfg

    def test_read_config_missing_file_returns_empty(self):
        cfg = read_config("/nonexistent/config.env")
        assert cfg == {}

    def test_write_config_updates_value(self):
        write_config(str(self.config), {"SUBSCRIPTION_URL": "https://new.com/sub/NEW"})
        cfg = read_config(str(self.config))
        assert cfg["SUBSCRIPTION_URL"] == "https://new.com/sub/NEW"

    def test_write_config_preserves_other_keys(self):
        write_config(str(self.config), {"SUBSCRIPTION_URL": "https://new.com/sub/NEW"})
        cfg = read_config(str(self.config))
        assert cfg["SYNC_INTERVAL"] == "10min"

    def test_write_config_adds_new_key(self):
        write_config(str(self.config), {"NEW_KEY": "value"})
        cfg = read_config(str(self.config))
        assert cfg["NEW_KEY"] == "value"


class TestGetLastLogLine:
    def setup_method(self):
        self.tmp = Path(tempfile.mkdtemp())

    def teardown_method(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_returns_last_line(self):
        log = self.tmp / "sync.log"
        log.write_text("line 1\nline 2\nline 3\n")
        assert get_last_log_line(str(log)) == "line 3"

    def test_missing_file_returns_none(self):
        assert get_last_log_line("/nonexistent/sync.log") is None

    def test_empty_file_returns_none(self):
        log = self.tmp / "empty.log"
        log.write_text("")
        assert get_last_log_line(str(log)) is None


class TestDetectReloadMode:
    def test_returns_string(self):
        mode = detect_reload_mode()
        assert mode in ("systemd", "container", "unknown")
