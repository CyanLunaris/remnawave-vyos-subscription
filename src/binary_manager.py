"""
Download and verify sing-box binary and geo rule-set data files.

sing-box releases: https://github.com/SagerNet/sing-box/releases
geoip rule-sets:   https://github.com/SagerNet/sing-geoip/tree/rule-set
geosite rule-sets: https://github.com/SagerNet/sing-geosite/tree/rule-set
"""
from __future__ import annotations
import json
import logging
import os
import platform
import stat
import tarfile
import tempfile
import urllib.request
from pathlib import Path
from typing import List

log = logging.getLogger(__name__)

GITHUB_API = "https://api.github.com"
SING_BOX_REPO = "SagerNet/sing-box"
GEOIP_RULE_SET_BASE = "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set"
GEOSITE_RULE_SET_BASE = "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set"


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


def ensure_rule_sets(rule_set_dir: str, ip_codes: List[str], site_codes: List[str]) -> None:
    """Ensure rule-set .srs files exist in rule_set_dir. Download if missing."""
    for code in ip_codes:
        path = Path(rule_set_dir) / f"geoip-{code}.srs"
        if not path.exists():
            log.info("Downloading geoip-%s.srs...", code)
            url = f"{GEOIP_RULE_SET_BASE}/geoip-{code}.srs"
            _download_file(url, str(path))
            log.info("geoip-%s.srs saved to %s", code, path)

    for code in site_codes:
        path = Path(rule_set_dir) / f"geosite-{code}.srs"
        if not path.exists():
            log.info("Downloading geosite-%s.srs...", code)
            url = f"{GEOSITE_RULE_SET_BASE}/geosite-{code}.srs"
            _download_file(url, str(path))
            log.info("geosite-%s.srs saved to %s", code, path)


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


def _fetch_latest_release(repo: str) -> dict:
    url = f"{GITHUB_API}/repos/{repo}/releases/latest"
    req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())


def _download_file(url: str, dest: str) -> None:
    Path(dest).parent.mkdir(parents=True, exist_ok=True)
    req = urllib.request.Request(url, headers={"User-Agent": "remnaproxy-sync/1.0"})
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
                    file_obj = tar.extractfile(member)
                    if file_obj is None:
                        raise RuntimeError("sing-box member is not a regular file")
                    Path(dest).write_bytes(file_obj.read())
                    break
            else:
                raise RuntimeError("sing-box binary not found in archive")
    # Make executable
    current = os.stat(dest).st_mode
    os.chmod(dest, current | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
