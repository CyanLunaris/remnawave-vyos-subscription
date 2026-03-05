import json
import pytest
import tempfile
from pathlib import Path
from src.state_manager import StateManager
from src.uri_parser import ParsedNode


def make_node(name: str) -> ParsedNode:
    return ParsedNode(
        protocol="vless", host=f"{name}.example.com", port=443,
        name=name, uuid="uuid", security="reality",
        reality_pbk="KEY", reality_sid="sid",
    )


class TestStateManager:
    def setup_method(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.nodes_file = self.tmp / "nodes.json"
        self.state_file = self.tmp / "state.json"
        self.sm = StateManager(str(self.nodes_file), str(self.state_file))

    def test_save_and_load_nodes(self):
        nodes = [make_node("NL-1"), make_node("DE-1")]
        self.sm.save_nodes(nodes)
        loaded = self.sm.load_nodes()
        assert len(loaded) == 2
        assert loaded[0].host == "NL-1.example.com"
        assert loaded[1].host == "DE-1.example.com"

    def test_load_nodes_missing_file_returns_empty(self):
        assert self.sm.load_nodes() == []

    def test_current_node_index_default_zero(self):
        assert self.sm.get_current_index() == 0

    def test_set_current_index(self):
        self.sm.set_current_index(2)
        assert self.sm.get_current_index() == 2
        # Persists across new instance
        sm2 = StateManager(str(self.nodes_file), str(self.state_file))
        assert sm2.get_current_index() == 2

    def test_increment_index_wraps(self):
        nodes = [make_node("A"), make_node("B"), make_node("C")]
        self.sm.save_nodes(nodes)
        self.sm.set_current_index(2)
        new_idx = self.sm.rotate_node()
        assert new_idx == 0  # wraps to beginning

    def test_increment_index_normal(self):
        nodes = [make_node("A"), make_node("B"), make_node("C")]
        self.sm.save_nodes(nodes)
        self.sm.set_current_index(0)
        new_idx = self.sm.rotate_node()
        assert new_idx == 1

    def test_get_current_node(self):
        nodes = [make_node("A"), make_node("B")]
        self.sm.save_nodes(nodes)
        self.sm.set_current_index(1)
        node = self.sm.get_current_node()
        assert node.name == "B"

    def test_get_current_node_empty_returns_none(self):
        assert self.sm.get_current_node() is None

    def test_fail_count(self):
        self.sm.increment_fail_count()
        self.sm.increment_fail_count()
        assert self.sm.get_fail_count() == 2
        self.sm.reset_fail_count()
        assert self.sm.get_fail_count() == 0
