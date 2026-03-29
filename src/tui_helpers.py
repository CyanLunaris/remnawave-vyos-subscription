"""
Pure helper functions for the TUI — no Textual dependency.
These are tested independently from the UI.
"""
from __future__ import annotations
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, Optional

from .state_manager import StateManager


def get_status(nodes_file: str, state_file: str) -> Dict[str, Any]:
    """Return current service status as a plain dict."""
    sm = StateManager(nodes_file, state_file)
    nodes = sm.load_nodes()
    node = sm.get_current_node()
    return {
        "current_node_name": node.name if node else "N/A",
        "current_node_host": node.host if node else "N/A",
        "current_node_port": node.port if node else 0,
        "current_node_protocol": node.protocol if node else "N/A",
        "current_index": sm.get_current_index(),
        "node_count": len(nodes),
        "fail_count": sm.get_fail_count(),
    }


def read_config(config_path: str) -> Dict[str, str]:
    """Read config.env and return key→value dict (skips comments and blanks)."""
    result: Dict[str, str] = {}
    try:
        for line in Path(config_path).read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            result[key.strip()] = value.strip()
    except FileNotFoundError:
        pass
    return result


def write_config(config_path: str, updates: Dict[str, str]) -> None:
    """Update specific keys in config.env, preserving all other lines.

    Uses an atomic write (temp file + os.replace) to avoid config corruption
    if the process is interrupted mid-write.
    """
    path = Path(config_path)
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True) if path.exists() else []

    updated_keys: set = set()
    new_lines = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("#") or "=" not in stripped:
            new_lines.append(line)
            continue
        key = stripped.split("=", 1)[0].strip()
        if key in updates:
            new_lines.append(f"{key}={updates[key]}\n")
            updated_keys.add(key)
        else:
            new_lines.append(line)

    # Append any new keys not already in file
    for key, value in updates.items():
        if key not in updated_keys:
            new_lines.append(f"{key}={value}\n")

    content = "".join(new_lines)
    # Atomic write: write to temp file in same directory, then rename
    fd, tmp_path = tempfile.mkstemp(dir=path.parent, prefix=".tmp-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
        os.replace(tmp_path, str(path))
    except Exception:
        os.unlink(tmp_path)
        raise


def get_last_log_line(log_path: str) -> Optional[str]:
    """Return the last non-empty line of a log file, or None if unavailable."""
    try:
        text = Path(log_path).read_text(encoding="utf-8")
        lines = [line for line in text.splitlines() if line.strip()]
        return lines[-1] if lines else None
    except (FileNotFoundError, OSError):
        return None


def detect_reload_mode() -> str:
    """Detect whether we're running under systemd or in a container."""
    if Path("/run/systemd/system").exists():
        return "systemd"
    if Path("/.dockerenv").exists():
        return "container"
    return "unknown"


def reload_sing_box() -> bool:
    """Reload or restart sing-box. Returns True on success."""
    mode = detect_reload_mode()
    if mode == "systemd":
        result = subprocess.run(
            ["/bin/systemctl", "reload-or-restart", "sing-box"],
            capture_output=True,
        )
        return result.returncode == 0
    # Container / unknown mode: SIGHUP to sing-box process
    result = subprocess.run(
        ["pkill", "-HUP", "sing-box"],
        capture_output=True,
    )
    return result.returncode == 0
