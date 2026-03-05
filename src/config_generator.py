"""
Generate sing-box config.json from a ParsedNode.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Dict, List

from .uri_parser import ParsedNode


@dataclass
class ConfigSettings:
    tun_interface: str = "tun0"
    tun_address: str = "172.19.0.1/30"
    geo_direct_ip: List[str] = field(default_factory=lambda: ["private", "ru"])
    geo_direct_site: List[str] = field(default_factory=lambda: ["ru"])
    geoip_path: str = "/etc/sing-box/geoip.db"
    geosite_path: str = "/etc/sing-box/geosite.db"
    dns_server: str = "8.8.8.8"


def generate_config(node: ParsedNode, settings: ConfigSettings) -> Dict[str, Any]:
    return {
        "log": {"level": "warn", "output": "/var/log/remnawave/sing-box.log"},
        "dns": _build_dns(settings),
        "inbounds": [_build_tun_inbound(settings)],
        "outbounds": [_build_outbound(node), _build_direct_outbound(), _build_dns_outbound()],
        "route": _build_route(settings),
    }


# ── Inbounds ──────────────────────────────────────────────────────────────────

def _build_tun_inbound(s: ConfigSettings) -> Dict[str, Any]:
    return {
        "type": "tun",
        "tag": "tun-in",
        "interface_name": s.tun_interface,
        "inet4_address": s.tun_address,
        "mtu": 1500,
        "auto_route": False,
        "strict_route": False,
        "stack": "system",
        "sniff": True,
    }


# ── Outbounds ─────────────────────────────────────────────────────────────────

def _build_outbound(node: ParsedNode) -> Dict[str, Any]:
    builders = {
        "vless": _build_vless_outbound,
        "vmess": _build_vmess_outbound,
        "trojan": _build_trojan_outbound,
    }
    builder = builders.get(node.protocol)
    if builder is None:
        raise ValueError(f"Unsupported protocol: {node.protocol}")
    return builder(node)


def _build_vless_outbound(node: ParsedNode) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "type": "vless",
        "tag": "proxy",
        "server": node.host,
        "server_port": node.port,
        "uuid": node.uuid,
    }
    if node.flow:
        out["flow"] = node.flow
    out["tls"] = _build_tls(node)
    transport = _build_transport(node)
    if transport:
        out["transport"] = transport
    return out


def _build_vmess_outbound(node: ParsedNode) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "type": "vmess",
        "tag": "proxy",
        "server": node.host,
        "server_port": node.port,
        "uuid": node.uuid,
        "security": node.vmess_security or "auto",
        "alter_id": node.alter_id,
    }
    if node.security == "tls":
        out["tls"] = _build_tls(node)
    transport = _build_transport(node)
    if transport:
        out["transport"] = transport
    return out


def _build_trojan_outbound(node: ParsedNode) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "type": "trojan",
        "tag": "proxy",
        "server": node.host,
        "server_port": node.port,
        "password": node.password,
        "tls": _build_tls(node),
    }
    transport = _build_transport(node)
    if transport:
        out["transport"] = transport
    return out


def _build_direct_outbound() -> Dict[str, Any]:
    return {"type": "direct", "tag": "direct"}


def _build_dns_outbound() -> Dict[str, Any]:
    return {"type": "dns", "tag": "dns-out"}


# ── TLS / Transport helpers ───────────────────────────────────────────────────

def _build_tls(node: ParsedNode) -> Dict[str, Any]:
    if node.security == "none" and node.protocol != "trojan":
        return {"enabled": False}

    tls: Dict[str, Any] = {"enabled": True, "server_name": node.sni or node.host}

    if node.fingerprint:
        tls["utls"] = {"enabled": True, "fingerprint": node.fingerprint}

    if node.security == "reality":
        tls["reality"] = {
            "enabled": True,
            "public_key": node.reality_pbk,
            "short_id": node.reality_sid,
        }

    return tls


def _build_transport(node: ParsedNode) -> Dict[str, Any]:
    if node.network == "ws":
        t: Dict[str, Any] = {"type": "ws", "path": node.ws_path or "/"}
        if node.ws_host:
            t["headers"] = {"Host": node.ws_host}
        return t
    if node.network == "grpc":
        return {"type": "grpc", "service_name": node.grpc_service}
    if node.network == "http":
        return {"type": "http", "path": node.ws_path or "/"}
    return {}  # tcp — no transport block needed


# ── DNS ───────────────────────────────────────────────────────────────────────

def _build_dns(s: ConfigSettings) -> Dict[str, Any]:
    return {
        "servers": [
            {"tag": "remote", "address": f"https://{s.dns_server}/dns-query", "detour": "proxy"},
            {"tag": "local", "address": "1.1.1.1", "detour": "direct"},
        ],
        "rules": [
            {"geosite": s.geo_direct_site, "server": "local"},
        ],
        "final": "remote",
    }


# ── Routing ───────────────────────────────────────────────────────────────────

def _build_route(s: ConfigSettings) -> Dict[str, Any]:
    rules: List[Dict[str, Any]] = [
        {"protocol": "dns", "outbound": "dns-out"},
        {"ip_is_private": True, "outbound": "direct"},
    ]
    if s.geo_direct_ip:
        non_private = [g for g in s.geo_direct_ip if g != "private"]
        if non_private:
            rules.append({"geoip": non_private, "outbound": "direct"})
    if s.geo_direct_site:
        rules.append({"geosite": s.geo_direct_site, "outbound": "direct"})

    return {
        "rules": rules,
        "final": "proxy",
        "geoip": {"path": s.geoip_path},
        "geosite": {"path": s.geosite_path},
    }
