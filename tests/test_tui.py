import signal
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from src.sync import load_env

pytest.importorskip("textual")

from src.tui import KernelSwitchModal


@pytest.fixture()
def config_file():
    with tempfile.TemporaryDirectory() as tmp:
        config = Path(tmp) / "config.env"
        config.write_text("PROXY_KERNEL=singbox\n")
        yield config


def test_do_switch_standalone_writes_kernel_and_sends_sigterm(config_file):
    logs = []
    modal = KernelSwitchModal(None, "xray", str(config_file))

    with patch("os.kill") as kill_mock:
        modal._do_switch_standalone(logs.append)

    env = load_env(str(config_file))
    assert env["PROXY_KERNEL"] == "xray"
    kill_mock.assert_called_once_with(1, signal.SIGTERM)
    assert any("will run sync on startup" in entry for entry in logs)


def test_do_switch_standalone_reverts_kernel_if_sigterm_fails(config_file):
    logs = []
    modal = KernelSwitchModal(None, "xray", str(config_file))

    with patch("os.kill", side_effect=PermissionError("no signal permission")):
        with pytest.raises(PermissionError):
            modal._do_switch_standalone(logs.append)

    env = load_env(str(config_file))
    assert env["PROXY_KERNEL"] == "singbox"
    assert any("Restart failed — reverting PROXY_KERNEL to singbox" in entry for entry in logs)
