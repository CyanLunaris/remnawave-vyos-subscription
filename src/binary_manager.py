"""
Download and verify sing-box binary and geo data files.

sing-box releases: https://github.com/SagerNet/sing-box/releases
geoip.db:          https://github.com/SagerNet/sing-geoip/releases
geosite.db:        https://github.com/SagerNet/sing-geosite/releases
"""
from __future__ import annotations
import hashlib
import json
import logging
import os
import platform
import shutil
import stat
import tarfile
import tempfile
import urllib.request
from pathlib import Path

log = logging.getLogger(__name__)

GITHUB_API = "https://api.github.com"
SING_BOX_REPO = "SagerNet/sing-box"
GEOIP_REPO = "SagerNet/sing-geoip"
GEOSITE_REPO = "SagerNet/sing-geosite"


def ensure_sing_box(install_path: str) -> str:
    """Ensure sing-box binary exists at install_path. Download if missing."""
    p = Path(install_path)
    if p.exists() and os.access(str(p), os.X_OK):
        log.info("sing-box already present: %s", install_path)
        return install_path

    log.info("Downloading sing-box...")
    url = _get_sing_box_download_url()
    _download_sing_box(url, install_path)
    log.info("sing-box installed to %s", install_path)
    return install_path


def ensure_geo_files(geoip_path: str, geosite_path: str) -> None:
    """Ensure geoip.db and geosite.db exist. Download if missing."""
    if not Path(geoip_path).exists():
        log.info("Downloading geoip.db...")
        url = _get_latest_asset_url(GEOIP_REPO, "geoip.db")
        _download_file(url, geoip_path)
        log.info("geoip.db saved to %s", geoip_path)

    if not Path(geosite_path).exists():
        log.info("Downloading geosite.db...")
        url = _get_latest_asset_url(GEOSITE_REPO, "geosite.db")
        _download_file(url, geosite_path)
        log.info("geosite.db saved to %s", geosite_path)


# ── Internal helpers ──────────────────────────────────────────────────────────

def _get_arch() -> str:
    machine = platform.machine().lower()
    mapping = {
        "x86_64": "amd64", "amd64": "amd64",
        "aarch64": "arm64", "arm64": "arm64",
        "armv7l": "armv7",
    }
    return mapping.get(machine, "amd64")


def _get_sing_box_download_url() -> str:
    release = _fetch_latest_release(SING_BOX_REPO)
    version = release["tag_name"].lstrip("v")
    arch = _get_arch()
    # e.g. sing-box-1.9.0-linux-amd64.tar.gz
    asset_name = f"sing-box-{version}-linux-{arch}.tar.gz"
    for asset in release["assets"]:
        if asset["name"] == asset_name:
            return asset["browser_download_url"]
    raise RuntimeError(f"Could not find asset {asset_name} in sing-box release")


def _get_latest_asset_url(repo: str, filename: str) -> str:
    release = _fetch_latest_release(repo)
    for asset in release["assets"]:
        if asset["name"] == filename:
            return asset["browser_download_url"]
    raise RuntimeError(f"Could not find {filename} in {repo} release")


def _fetch_latest_release(repo: str) -> dict:
    url = f"{GITHUB_API}/repos/{repo}/releases/latest"
    req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())


def _download_file(url: str, dest: str) -> None:
    Path(dest).parent.mkdir(parents=True, exist_ok=True)
    req = urllib.request.Request(url, headers={"User-Agent": "remnawave-sync/1.0"})
    with urllib.request.urlopen(req, timeout=120) as resp:
        Path(dest).write_bytes(resp.read())


def _download_sing_box(url: str, dest: str) -> None:
    Path(dest).parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        tar_path = os.path.join(tmp, "sing-box.tar.gz")
        _download_file(url, tar_path)
        with tarfile.open(tar_path, "r:gz") as tar:
            # Find the sing-box binary inside the archive
            for member in tar.getmembers():
                if member.name.endswith("/sing-box") or member.name == "sing-box":
                    member.name = "sing-box"
                    tar.extract(member, tmp)
                    break
            else:
                raise RuntimeError("sing-box binary not found in archive")
        extracted = os.path.join(tmp, "sing-box")
        shutil.copy2(extracted, dest)
    # Make executable
    current = os.stat(dest).st_mode
    os.chmod(dest, current | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
