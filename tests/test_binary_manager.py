import io
import os
import stat
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.binary_manager import (
    ensure_xray, ensure_tun2socks, ensure_xray_rule_sets,
    _get_arch, _download_file_atomic,
)


def _make_zip(binary_name: str, content: bytes = b"#!/bin/sh\n") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(binary_name, content)
    return buf.getvalue()


def _fake_urlopen(url_data: dict):
    """Return a context manager that yields fake responses based on URL."""
    class FakeResponse:
        def __init__(self, data):
            self._data = data
        def read(self):
            return self._data
        def __enter__(self):
            return self
        def __exit__(self, *a):
            pass

    def side_effect(req, timeout=None):
        url = req.full_url if hasattr(req, "full_url") else str(req)
        for key, data in url_data.items():
            if key in url:
                return FakeResponse(data)
        raise ValueError(f"Unexpected URL: {url}")

    return side_effect


class TestGetArch:
    def test_amd64(self):
        with patch("platform.machine", return_value="x86_64"):
            assert _get_arch() == "amd64"

    def test_arm64(self):
        with patch("platform.machine", return_value="aarch64"):
            assert _get_arch() == "arm64"

    def test_unknown_defaults_amd64(self):
        with patch("platform.machine", return_value="mips"):
            assert _get_arch() == "amd64"


class TestEnsureXray:
    def test_skips_if_already_present(self, tmp_path):
        xray = tmp_path / "xray"
        xray.write_bytes(b"binary")
        xray.chmod(xray.stat().st_mode | stat.S_IXUSR)
        result = ensure_xray(str(xray))
        assert result == str(xray)

    def test_downloads_and_installs(self, tmp_path):
        xray_path = tmp_path / "xray"
        release_json = b'{"tag_name": "v1.8.24", "assets": [{"name": "Xray-linux-64.zip", "browser_download_url": "https://github.com/fake/xray.zip"}]}'
        zip_data = _make_zip("xray")

        responses = {
            "api.github.com": release_json,
            "fake/xray.zip": zip_data,
        }

        with patch("platform.machine", return_value="x86_64"):
            with patch("urllib.request.urlopen", side_effect=_fake_urlopen(responses)):
                with patch("subprocess.run") as mock_run:
                    mock_run.return_value = MagicMock(
                        stdout="Xray 1.8.24 (Xray, Penetrates Everything)\n",
                        returncode=0,
                    )
                    result = ensure_xray(str(xray_path))

        assert result == str(xray_path)
        assert xray_path.exists()
        assert os.access(str(xray_path), os.X_OK)

    def test_version_file_written(self, tmp_path):
        xray_path = tmp_path / "xray"
        release_json = b'{"tag_name": "v1.8.24", "assets": [{"name": "Xray-linux-64.zip", "browser_download_url": "https://github.com/fake/xray.zip"}]}'
        zip_data = _make_zip("xray")

        responses = {
            "api.github.com": release_json,
            "fake/xray.zip": zip_data,
        }

        with patch("platform.machine", return_value="x86_64"):
            with patch("urllib.request.urlopen", side_effect=_fake_urlopen(responses)):
                with patch("subprocess.run") as mock_run:
                    mock_run.return_value = MagicMock(
                        stdout="Xray 1.8.24 (Xray, Penetrates Everything)\n",
                        returncode=0,
                    )
                    ensure_xray(str(xray_path))

        version_file = tmp_path / ".version"
        assert version_file.exists()
        assert version_file.read_text().strip() == "1.8.24"

    def test_arm64_asset_name(self, tmp_path):
        xray_path = tmp_path / "xray"
        release_json = b'{"tag_name": "v1.8.24", "assets": [{"name": "Xray-linux-arm64-v8a.zip", "browser_download_url": "https://github.com/fake/xray-arm64.zip"}]}'
        zip_data = _make_zip("xray")

        responses = {
            "api.github.com": release_json,
            "fake/xray-arm64.zip": zip_data,
        }

        with patch("platform.machine", return_value="aarch64"):
            with patch("urllib.request.urlopen", side_effect=_fake_urlopen(responses)):
                with patch("subprocess.run", return_value=MagicMock(stdout="Xray 1.8.24\n", returncode=0)):
                    ensure_xray(str(xray_path))

        assert xray_path.exists()


class TestEnsureTun2socks:
    def test_skips_if_present(self, tmp_path):
        t = tmp_path / "tun2socks"
        t.write_bytes(b"binary")
        t.chmod(t.stat().st_mode | stat.S_IXUSR)
        assert ensure_tun2socks(str(t)) == str(t)

    def test_downloads_amd64(self, tmp_path):
        t2s_path = tmp_path / "tun2socks"
        release_json = b'{"tag_name": "v2.5.2", "assets": [{"name": "tun2socks-linux-amd64.zip", "browser_download_url": "https://github.com/fake/t2s.zip"}]}'
        zip_data = _make_zip("tun2socks")

        responses = {
            "api.github.com": release_json,
            "fake/t2s.zip": zip_data,
        }

        with patch("platform.machine", return_value="x86_64"):
            with patch("urllib.request.urlopen", side_effect=_fake_urlopen(responses)):
                ensure_tun2socks(str(t2s_path))

        assert t2s_path.exists()
        assert os.access(str(t2s_path), os.X_OK)


class TestEnsureXrayRuleSets:
    def test_downloads_missing_files(self, tmp_path):
        xray_dir = str(tmp_path)
        geoip_data = b"fake-geoip-data"
        geosite_data = b"fake-geosite-data"

        responses = {
            "geoip.dat": geoip_data,
            "dlc.dat": geosite_data,
        }

        with patch("urllib.request.urlopen", side_effect=_fake_urlopen(responses)):
            ensure_xray_rule_sets(xray_dir)

        assert (tmp_path / "geoip.dat").read_bytes() == geoip_data
        assert (tmp_path / "geosite.dat").read_bytes() == geosite_data

    def test_skips_existing_files(self, tmp_path):
        (tmp_path / "geoip.dat").write_bytes(b"existing")
        (tmp_path / "geosite.dat").write_bytes(b"existing")

        with patch("urllib.request.urlopen") as mock_open:
            ensure_xray_rule_sets(str(tmp_path))

        mock_open.assert_not_called()

    def test_atomic_download_cleans_tmp_on_failure(self, tmp_path):
        dest = tmp_path / "geoip.dat"

        def fail_open(req, timeout=None):
            raise ConnectionError("network error")

        with patch("urllib.request.urlopen", side_effect=fail_open):
            with pytest.raises(ConnectionError):
                _download_file_atomic("https://example.com/geoip.dat", str(dest))

        assert not dest.exists()
        assert not (tmp_path / "geoip.dat.tmp").exists()
