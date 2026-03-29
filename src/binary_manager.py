"""
Download and verify sing-box binary and geo rule-set data files.

sing-box releases: https://github.com/SagerNet/sing-box/releases
geoip rule-sets:   https://github.com/SagerNet/sing-geoip/tree/rule-set
geosite rule-sets: https://github.com/SagerNet/sing-geosite/tree/rule-set
xray releases:     https://github.com/XTLS/Xray-core/releases
tun2socks:         https://github.com/xjasonlyu/tun2socks/releases
xray geoip:        https://github.com/v2fly/geoip/releases
xray geosite:      https://github.com/v2fly/domain-list-community/releases
"""
from __future__ import annotations
import json
import logging
import os
import platform
import stat
import subprocess
import tarfile
import tempfile
import urllib.request
import zipfile
from pathlib import Path
from typing import List

log = logging.getLogger(__name__)

GITHUB_API = "https://api.github.com"
SING_BOX_REPO = "SagerNet/sing-box"
XRAY_REPO = "XTLS/Xray-core"
TUN2SOCKS_REPO = "xjasonlyu/tun2socks"
GEOIP_RULE_SET_BASE = "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set"
GEOSITE_RULE_SET_BASE = "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set"
XRAY_GEOIP_URL = "https://github.com/v2fly/geoip/releases/latest/download/geoip.dat"
XRAY_GEOSITE_URL = "https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat"


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


def ensure_xray(install_path: str) -> str:
    """Ensure xray binary exists at install_path. Download if missing."""
    p = Path(install_path)
    if p.exists() and os.access(str(p), os.X_OK):
        log.info("xray already present: %s", install_path)
        return install_path

    log.info("Downloading xray...")
    release = _fetch_latest_release(XRAY_REPO)
    arch = _get_arch()
    asset_map = {"amd64": "Xray-linux-64.zip", "arm64": "Xray-linux-arm64-v8a.zip"}
    asset_name = asset_map.get(arch, "Xray-linux-64.zip")
    url = next(
        (a["browser_download_url"] for a in release["assets"] if a["name"] == asset_name),
        None,
    )
    if url is None:
        raise RuntimeError(f"Could not find asset {asset_name} in xray release")

    _download_zip_binary(url, "xray", install_path)
    log.info("xray installed to %s", install_path)

    # Store version for status bar
    version_file = Path(install_path).parent / ".version"
    try:
        result = subprocess.run(
            [install_path, "version"], capture_output=True, text=True, timeout=5
        )
        first_line = result.stdout.strip().splitlines()[0] if result.stdout.strip() else ""
        # "Xray 1.8.24 (Xray, Penetrates Everything) ..."
        parts = first_line.split()
        version_str = parts[1] if len(parts) >= 2 else "?.?.?"
        version_file.write_text(version_str)
    except Exception:
        version_file.write_text("?.?.?")

    return install_path


def ensure_tun2socks(install_path: str) -> str:
    """Ensure tun2socks binary exists at install_path. Download if missing."""
    p = Path(install_path)
    if p.exists() and os.access(str(p), os.X_OK):
        log.info("tun2socks already present: %s", install_path)
        return install_path

    log.info("Downloading tun2socks...")
    release = _fetch_latest_release(TUN2SOCKS_REPO)
    arch = _get_arch()
    asset_map = {"amd64": "tun2socks-linux-amd64.zip", "arm64": "tun2socks-linux-arm64.zip"}
    asset_name = asset_map.get(arch, "tun2socks-linux-amd64.zip")
    url = next(
        (a["browser_download_url"] for a in release["assets"] if a["name"] == asset_name),
        None,
    )
    if url is None:
        raise RuntimeError(f"Could not find asset {asset_name} in tun2socks release")

    _download_zip_binary(url, "tun2socks", install_path)
    log.info("tun2socks installed to %s", install_path)
    return install_path


def ensure_xray_rule_sets(xray_dir: str) -> None:
    """Ensure xray geo data files exist in xray_dir. Download if missing."""
    Path(xray_dir).mkdir(parents=True, exist_ok=True)

    geoip_path = Path(xray_dir) / "geoip.dat"
    if not geoip_path.exists():
        log.info("Downloading xray geoip.dat...")
        _download_file_atomic(XRAY_GEOIP_URL, str(geoip_path))
        log.info("xray geoip.dat saved to %s", geoip_path)

    geosite_path = Path(xray_dir) / "geosite.dat"
    if not geosite_path.exists():
        log.info("Downloading xray geosite.dat...")
        _download_file_atomic(XRAY_GEOSITE_URL, str(geosite_path))
        log.info("xray geosite.dat saved to %s", geosite_path)


def ensure_rule_sets(rule_set_dir: str, ip_codes: List[str], site_codes: List[str]) -> None:
    """Ensure rule-set .srs files exist in rule_set_dir. Download if missing."""
    for code in ip_codes:
        path = Path(rule_set_dir) / f"geoip-{code}.srs"
        if not path.exists():
            log.info("Downloading geoip-%s.srs...", code)
            url = f"{GEOIP_RULE_SET_BASE}/geoip-{code}.srs"
            _download_file_atomic(url, str(path))
            log.info("geoip-%s.srs saved to %s", code, path)

    for code in site_codes:
        path = Path(rule_set_dir) / f"geosite-{code}.srs"
        if not path.exists():
            log.info("Downloading geosite-%s.srs...", code)
            url = f"{GEOSITE_RULE_SET_BASE}/geosite-{code}.srs"
            _download_file_atomic(url, str(path))
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


def _download_file_atomic(url: str, dest: str) -> None:
    """Download url to dest atomically via a .tmp file."""
    dest_path = Path(dest)
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest_path.parent / (dest_path.name + ".tmp")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "remnaproxy-sync/1.0"})
        with urllib.request.urlopen(req, timeout=120) as resp:
            tmp.write_bytes(resp.read())
        tmp.rename(dest_path)
    except Exception:
        tmp.unlink(missing_ok=True)
        raise


def _download_zip_binary(url: str, binary_name: str, dest: str) -> None:
    """Download a .zip archive and extract the named binary to dest."""
    dest_path = Path(dest)
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest_path.parent / (dest_path.name + ".tmp")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "remnaproxy-sync/1.0"})
        with urllib.request.urlopen(req, timeout=120) as resp:
            zip_data = resp.read()
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as zf:
            zf.write(zip_data)
            zip_path = zf.name
        try:
            with zipfile.ZipFile(zip_path) as zf:
                names = zf.namelist()
                match = next(
                    (n for n in names if n == binary_name or n.endswith("/" + binary_name)),
                    None,
                )
                if match is None:
                    raise RuntimeError(f"{binary_name} not found in archive; entries: {names}")
                tmp.write_bytes(zf.read(match))
        finally:
            os.unlink(zip_path)
        current = os.stat(str(tmp)).st_mode
        os.chmod(str(tmp), current | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        tmp.rename(dest_path)
    except Exception:
        tmp.unlink(missing_ok=True)
        raise


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
