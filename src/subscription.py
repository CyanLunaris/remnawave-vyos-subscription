"""
Fetch and decode Remnawave subscription.

Remnawave returns different formats depending on User-Agent:
  - sfa/sfi/sfm/sft/singbox → sing-box JSON (outbounds array)
  - clash/mihomo            → Clash YAML
  - fallback                → Base64-encoded URI list (vless://, vmess://, trojan://)

We use User-Agent "sfa/1.0" to get sing-box JSON and parse proxy outbounds directly.
Falls back to base64/plain URI parsing for older panel versions.
"""
from __future__ import annotations
import base64
import json
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

from .uri_parser import ParsedNode, parse_uri

TIMEOUT_SECONDS = 15
# Use sing-box UA so Remnawave returns JSON format and recognises us as a valid client
USER_AGENT = "sfa/1.0"

# Some Remnawave panels require device fingerprint headers to return real nodes
_DEVICE_HEADERS = {
    "x-hwid": "remnaproxy-vyos",
    "x-device-os": "iOS",
    "x-ver-os": "18.3",
    "x-device-model": "iPhone 14 Pro Max",
}

_PROXY_TYPES = {"vless", "vmess", "trojan"}


def fetch_subscription(url: str) -> List[ParsedNode]:
    """Fetch subscription URL and return list of parsed nodes. Raises ConnectionError on failure."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **_DEVICE_HEADERS})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as resp:
            if resp.status != 200:
                raise ConnectionError(f"Subscription returned HTTP {resp.status}")
            raw = resp.read().decode("utf-8", errors="replace")
    except urllib.error.URLError as exc:
        raise ConnectionError(f"Failed to fetch subscription: {exc}") from exc
    return decode_subscription(raw)


def decode_subscription(raw: str) -> List[ParsedNode]:
    """Parse raw subscription response into nodes.

    Supports:
    - sing-box JSON (preferred, from sfa UA)
    - Plain URI list (vless://, vmess://, trojan://)
    - Base64-encoded URI list
    """
    if not raw.strip():
        return []

    # Try sing-box JSON first
    nodes = _try_parse_singbox_json(raw)
    if nodes is not None:
        return nodes

    # Fall back to URI list (plain or base64)
    text = _maybe_decode_base64(raw.strip())
    nodes = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        node = parse_uri(line)
        if node is not None:
            nodes.append(node)
    return nodes


# ── sing-box JSON parser ───────────────────────────────────────────────────────

def _try_parse_singbox_json(raw: str) -> Optional[List[ParsedNode]]:
    """Try to parse as sing-box JSON config. Returns None if not JSON."""
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(data, dict) or "outbounds" not in data:
        return None

    nodes: List[ParsedNode] = []
    for outbound in data["outbounds"]:
        if not isinstance(outbound, dict):
            continue
        if outbound.get("type") not in _PROXY_TYPES:
            continue
        # Skip dummy "App not supported" nodes
        if outbound.get("server") in ("0.0.0.0", "127.0.0.1", "") or outbound.get("server_port", 0) <= 1:
            continue
        node = _singbox_outbound_to_node(outbound)
        if node is not None:
            nodes.append(node)
    return nodes


def _singbox_outbound_to_node(o: Dict[str, Any]) -> Optional[ParsedNode]:
    """Convert a sing-box outbound dict to a ParsedNode."""
    try:
        proto = o["type"]
        host = o["server"]
        port = int(o["server_port"])
        name = o.get("tag", "")

        tls_cfg = o.get("tls", {})
        tls_enabled = tls_cfg.get("enabled", False)
        reality_cfg = tls_cfg.get("reality", {})
        utls_cfg = tls_cfg.get("utls", {})
        transport_cfg = o.get("transport", {})

        if reality_cfg.get("enabled"):
            security = "reality"
        elif tls_enabled:
            security = "tls"
        else:
            security = "none"

        network = transport_cfg.get("type", "tcp") if transport_cfg else "tcp"
        ws_path = transport_cfg.get("path", "") if transport_cfg else ""
        ws_host = (transport_cfg.get("headers") or {}).get("Host", "") if transport_cfg else ""
        grpc_service = transport_cfg.get("service_name", "") if transport_cfg else ""

        kwargs: Dict[str, Any] = dict(
            protocol=proto,
            host=host,
            port=port,
            name=name,
            security=security,
            network=network,
            sni=tls_cfg.get("server_name", ""),
            fingerprint=utls_cfg.get("fingerprint", "") if utls_cfg.get("enabled") else "",
            reality_pbk=reality_cfg.get("public_key", ""),
            reality_sid=reality_cfg.get("short_id", ""),
            ws_path=ws_path,
            ws_host=ws_host,
            grpc_service=grpc_service,
        )

        if proto in ("vless", "vmess"):
            kwargs["uuid"] = o.get("uuid", "")
        if proto == "vless":
            kwargs["flow"] = o.get("flow", "")
        if proto == "vmess":
            kwargs["alter_id"] = int(o.get("alter_id", 0))
            kwargs["vmess_security"] = o.get("security", "auto")
        if proto == "trojan":
            kwargs["password"] = o.get("password", "")

        return ParsedNode(**kwargs)
    except Exception:
        return None


# ── Base64 fallback ───────────────────────────────────────────────────────────

def _maybe_decode_base64(text: str) -> str:
    """Return decoded text if it looks like base64, otherwise original."""
    first_line = text.splitlines()[0] if text else ""
    known_schemes = ("vless://", "vmess://", "trojan://", "ss://", "ssr://")
    if any(first_line.startswith(s) for s in known_schemes):
        return text
    try:
        padding = 4 - len(text) % 4
        padded = text + ("=" * padding if padding != 4 else "")
        decoded = base64.b64decode(padded).decode("utf-8")
        if any(decoded.startswith(s) for s in known_schemes):
            return decoded
        first = decoded.splitlines()[0] if decoded.splitlines() else ""
        if any(first.startswith(s) for s in known_schemes):
            return decoded
    except Exception:
        pass
    return text
