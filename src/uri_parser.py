"""
Parse VLESS, VMess, and Trojan proxy URIs into structured node dicts.
"""
from __future__ import annotations
import base64
import json
import urllib.parse
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ParsedNode:
    protocol: str           # vless | vmess | trojan
    host: str
    port: int
    name: str = ""

    # VLESS / VMess shared
    uuid: str = ""
    security: str = "none"  # none | tls | reality
    network: str = "tcp"    # tcp | ws | grpc | http

    # TLS/Reality
    sni: str = ""
    fingerprint: str = ""

    # Reality-specific
    reality_pbk: str = ""   # public key
    reality_sid: str = ""   # short id

    # VLESS-specific
    flow: str = ""
    encryption: str = "none"

    # VMess-specific
    alter_id: int = 0
    vmess_security: str = "auto"

    # WebSocket transport
    ws_path: str = ""
    ws_host: str = ""

    # gRPC transport
    grpc_service: str = ""

    # Trojan-specific
    password: str = ""

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items()}


def parse_uri(uri: str) -> Optional[ParsedNode]:
    """Parse a proxy URI string. Returns None on failure."""
    if not uri:
        return None
    uri = uri.strip()
    if uri.startswith("vless://"):
        return _parse_vless(uri)
    if uri.startswith("vmess://"):
        return _parse_vmess(uri)
    if uri.startswith("trojan://"):
        return _parse_trojan(uri)
    return None


def _parse_vless(uri: str) -> Optional[ParsedNode]:
    try:
        # vless://uuid@host:port?params#name
        without_scheme = uri[len("vless://"):]
        if "#" in without_scheme:
            without_scheme, name = without_scheme.rsplit("#", 1)
            name = urllib.parse.unquote(name)
        else:
            name = ""

        if "?" in without_scheme:
            userinfo_host, raw_params = without_scheme.split("?", 1)
        else:
            userinfo_host, raw_params = without_scheme, ""

        uuid, hostport = userinfo_host.split("@", 1)
        host, port_str = _split_host_port(hostport)
        port = int(port_str)

        params = dict(urllib.parse.parse_qsl(raw_params))
        node = ParsedNode(
            protocol="vless",
            host=host,
            port=port,
            name=name,
            uuid=uuid,
            security=params.get("security", "none"),
            network=params.get("type", "tcp"),
            flow=params.get("flow", ""),
            encryption=params.get("encryption", "none"),
            sni=params.get("sni", ""),
            fingerprint=params.get("fp", ""),
            reality_pbk=params.get("pbk", ""),
            reality_sid=params.get("sid", ""),
            ws_path=urllib.parse.unquote(params.get("path", "")),
            ws_host=params.get("host", ""),
            grpc_service=params.get("serviceName", ""),
        )
        return node
    except Exception:
        return None


def _parse_vmess(uri: str) -> Optional[ParsedNode]:
    try:
        encoded = uri[len("vmess://"):]
        # Add padding if needed
        padding = 4 - len(encoded) % 4
        if padding != 4:
            encoded += "=" * padding
        data = json.loads(base64.b64decode(encoded).decode("utf-8"))

        tls_val = data.get("tls", "")
        security = "tls" if tls_val == "tls" else "none"
        network = data.get("net", "tcp")

        node = ParsedNode(
            protocol="vmess",
            host=data["add"],
            port=int(data["port"]),
            name=data.get("ps", ""),
            uuid=data["id"],
            security=security,
            network=network,
            sni=data.get("sni", "") or data.get("add", ""),
            fingerprint=data.get("fp", ""),
            alter_id=int(data.get("aid", 0)),
            vmess_security=data.get("scy", "auto"),
            ws_path=data.get("path", ""),
            ws_host=data.get("host", ""),
            grpc_service=data.get("path", ""),
        )
        return node
    except Exception:
        return None


def _parse_trojan(uri: str) -> Optional[ParsedNode]:
    try:
        without_scheme = uri[len("trojan://"):]
        if "#" in without_scheme:
            without_scheme, name = without_scheme.rsplit("#", 1)
            name = urllib.parse.unquote(name)
        else:
            name = ""

        if "?" in without_scheme:
            userinfo_host, raw_params = without_scheme.split("?", 1)
        else:
            userinfo_host, raw_params = without_scheme, ""

        password, hostport = userinfo_host.split("@", 1)
        host, port_str = _split_host_port(hostport)
        port = int(port_str)

        params = dict(urllib.parse.parse_qsl(raw_params))
        sni = params.get("sni", host)  # fall back to host

        node = ParsedNode(
            protocol="trojan",
            host=host,
            port=port,
            name=name,
            password=urllib.parse.unquote(password),
            security="tls",
            network=params.get("type", "tcp"),
            sni=sni,
            fingerprint=params.get("fp", ""),
        )
        return node
    except Exception:
        return None


def _split_host_port(hostport: str) -> tuple:
    """Handle IPv6 addresses like [::1]:443."""
    if hostport.startswith("["):
        bracket_end = hostport.index("]")
        host = hostport[1:bracket_end]
        port = hostport[bracket_end + 2:]
    else:
        host, port = hostport.rsplit(":", 1)
    return host, port
