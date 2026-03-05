"""
Fetch and decode Remnawave subscription.

Remnawave GET /sub/{token} returns either:
  - Plain text with one URI per line
  - Base64-encoded version of the same
"""
from __future__ import annotations
import base64
import urllib.error
import urllib.request
from typing import List

from .uri_parser import ParsedNode, parse_uri

TIMEOUT_SECONDS = 15
USER_AGENT = "remnawave-sync/1.0"


def fetch_subscription(url: str) -> List[ParsedNode]:
    """Fetch subscription URL and return list of parsed nodes. Raises ConnectionError on failure."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as resp:
            if resp.status != 200:
                raise ConnectionError(f"Subscription returned HTTP {resp.status}")
            raw = resp.read().decode("utf-8", errors="replace")
    except urllib.error.URLError as exc:
        raise ConnectionError(f"Failed to fetch subscription: {exc}") from exc
    return decode_subscription(raw)


def decode_subscription(raw: str) -> List[ParsedNode]:
    """Parse raw subscription text (plain or base64) into nodes."""
    if not raw.strip():
        return []

    text = _maybe_decode_base64(raw.strip())
    nodes: List[ParsedNode] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        node = parse_uri(line)
        if node is not None:
            nodes.append(node)
    return nodes


def _maybe_decode_base64(text: str) -> str:
    """Return decoded text if it looks like base64, otherwise original."""
    # URI lines start with known schemes — if no scheme found, assume base64
    first_line = text.splitlines()[0] if text else ""
    known_schemes = ("vless://", "vmess://", "trojan://", "ss://", "ssr://")
    if any(first_line.startswith(s) for s in known_schemes):
        return text
    try:
        padding = 4 - len(text) % 4
        padded = text + ("=" * padding if padding != 4 else "")
        decoded = base64.b64decode(padded).decode("utf-8")
        # Validate it looks like URI lines
        if any(decoded.startswith(s) for s in known_schemes):
            return decoded
        # Try per-line check
        first = decoded.splitlines()[0] if decoded.splitlines() else ""
        if any(first.startswith(s) for s in known_schemes):
            return decoded
    except Exception:
        pass
    return text
