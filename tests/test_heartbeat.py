import pytest
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock
from src.uri_parser import ParsedNode
from src.state_manager import StateManager



def make_node(name: str) -> ParsedNode:
    return ParsedNode(
        protocol="vless", host=f"{name}.com", port=443,
        name=name, uuid="uuid", security="reality",
        reality_pbk="KEY", reality_sid="sid",
    )


def make_sm_with_nodes(tmp_path, nodes, index=0):
    sm = StateManager(
        str(tmp_path / "nodes.json"),
        str(tmp_path / "state.json"),
    )
    sm.save_nodes(nodes)
    sm.set_current_index(index)
    return sm


class TestCheckConnectivity:
    def test_success_returns_true(self):
        from src.heartbeat import check_connectivity
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        with patch("urllib.request.urlopen", return_value=mock_resp):
            assert check_connectivity("cp.cloudflare.com", timeout=5) is True

    def test_204_returns_true(self):
        from src.heartbeat import check_connectivity
        mock_resp = MagicMock()
        mock_resp.status = 204
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        with patch("urllib.request.urlopen", return_value=mock_resp):
            assert check_connectivity("cp.cloudflare.com", timeout=5) is True

    def test_timeout_returns_false(self):
        import urllib.error
        from src.heartbeat import check_connectivity
        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("timeout")):
            assert check_connectivity("cp.cloudflare.com", timeout=1) is False

    def test_non_200_returns_false(self):
        from src.heartbeat import check_connectivity
        mock_resp = MagicMock()
        mock_resp.status = 503
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        with patch("urllib.request.urlopen", return_value=mock_resp):
            assert check_connectivity("cp.cloudflare.com", timeout=5) is False


class TestHeartbeatLogic:
    def setup_method(self):
        self.tmp = Path(tempfile.mkdtemp())

    def test_success_resets_fail_count(self):
        from src.heartbeat import run_heartbeat_check
        sm = make_sm_with_nodes(self.tmp, [make_node("A"), make_node("B")])
        sm.increment_fail_count()
        sm.increment_fail_count()

        with patch("src.heartbeat.check_connectivity", return_value=True):
            with patch("src.heartbeat._reload_proxy"):
                switched = run_heartbeat_check(sm, fail_threshold=2, heartbeat_host="h.com", timeout=5)

        assert switched is False
        assert sm.get_fail_count() == 0

    def test_single_failure_no_switch(self):
        from src.heartbeat import run_heartbeat_check
        sm = make_sm_with_nodes(self.tmp, [make_node("A"), make_node("B")])

        with patch("src.heartbeat.check_connectivity", return_value=False):
            with patch("src.heartbeat._reload_proxy"):
                switched = run_heartbeat_check(sm, fail_threshold=2, heartbeat_host="h.com", timeout=5)

        assert switched is False
        assert sm.get_fail_count() == 1
        assert sm.get_current_index() == 0

    def test_threshold_reached_switches_node(self):
        from src.heartbeat import run_heartbeat_check
        sm = make_sm_with_nodes(self.tmp, [make_node("A"), make_node("B"), make_node("C")])
        sm.increment_fail_count()  # already at 1

        with patch("src.heartbeat.check_connectivity", return_value=False):
            with patch("src.heartbeat._apply_new_node") as mock_apply:
                switched = run_heartbeat_check(sm, fail_threshold=2, heartbeat_host="h.com", timeout=5)

        assert switched is True
        assert sm.get_current_index() == 1
        assert sm.get_fail_count() == 0
        mock_apply.assert_called_once()

    def test_rotation_wraps_around(self):
        from src.heartbeat import run_heartbeat_check
        sm = make_sm_with_nodes(self.tmp, [make_node("A"), make_node("B")], index=1)
        sm.increment_fail_count()  # at 1

        with patch("src.heartbeat.check_connectivity", return_value=False):
            with patch("src.heartbeat._reload_proxy"):
                run_heartbeat_check(sm, fail_threshold=2, heartbeat_host="h.com", timeout=5)

        assert sm.get_current_index() == 0  # wrapped


class TestHeartbeatCooldown:
    def setup_method(self):
        self.tmp = Path(tempfile.mkdtemp())

    def test_cooldown_skips_check_after_rotation(self):
        from src.heartbeat import run_heartbeat_check
        sm = make_sm_with_nodes(self.tmp, [make_node("A"), make_node("B"), make_node("C")])
        sm.increment_fail_count()  # fail_count = 1

        # First call: reaches threshold, rotates, sets cooldown
        with patch("src.heartbeat.check_connectivity", return_value=False):
            with patch("src.heartbeat._apply_new_node"):
                switched = run_heartbeat_check(sm, fail_threshold=2, heartbeat_host="h.com", timeout=5, cooldown=2)
        assert switched is True
        assert sm.get_cooldown() == 2

        # Second call (connectivity still down): cooldown active, should NOT rotate again
        with patch("src.heartbeat.check_connectivity", return_value=False):
            with patch("src.heartbeat._apply_new_node") as mock_apply:
                switched2 = run_heartbeat_check(sm, fail_threshold=2, heartbeat_host="h.com", timeout=5, cooldown=2)
        assert switched2 is False
        assert mock_apply.call_count == 0
        assert sm.get_cooldown() == 1  # decremented

    def test_cooldown_zero_allows_check(self):
        from src.heartbeat import run_heartbeat_check
        sm = make_sm_with_nodes(self.tmp, [make_node("A"), make_node("B")])
        sm.set_cooldown(0)

        with patch("src.heartbeat.check_connectivity", return_value=False):
            with patch("src.heartbeat._apply_new_node"):
                switched = run_heartbeat_check(sm, fail_threshold=1, heartbeat_host="h.com", timeout=5, cooldown=2)
        assert switched is True  # no cooldown, rotates normally

    def test_success_resets_cooldown(self):
        from src.heartbeat import run_heartbeat_check
        from unittest.mock import call
        sm = make_sm_with_nodes(self.tmp, [make_node("A"), make_node("B")])
        # cooldown defaults to 0 so the guard does not fire; connectivity succeeds
        with patch("src.heartbeat.check_connectivity", return_value=True):
            with patch.object(sm, "set_cooldown", wraps=sm.set_cooldown) as mock_set_cooldown:
                run_heartbeat_check(sm, fail_threshold=2, heartbeat_host="h.com", timeout=5, cooldown=2)
        mock_set_cooldown.assert_called_with(0)
