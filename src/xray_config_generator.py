"""
Generate xray-core config JSON from a ParsedNode.

xhttp transport is not supported — raises ValueError with a clear message.
"""
from __future__ import annotations
from typing import Any, Dict, List

from .config_generator import ConfigSettings
from .uri_parser import ParsedNode


def generate_xray_config(node: ParsedNode, settings: ConfigSettings) -> Dict[str, Any]:
    return {
        "log": {
            "loglevel": "warning",
            "error": "/var/log/remnaproxy/xray-error.log",
        },
        "inbounds": [_build_socks_inbound()],
        "outbounds": [_build_outbound(node), {"tag": "direct", "protocol": "freedom"}],
        "routing": _build_routing(settings),
    }


# ── Inbound ────────────────────────────────────────────────────────────────────

def _build_socks_inbound() -> Dict[str, Any]:
    return {
        "tag": "socks-in",
        "protocol": "socks",
        "listen": "127.0.0.1",
        "port": 7891,
        "settings": {"udp": True},
    }


# ── Outbound ───────────────────────────────────────────────────────────────────

def _build_outbound(node: ParsedNode) -> Dict[str, Any]:
    builders = {
        "vless": _build_vless_outbound,
        "vmess": _build_vmess_outbound,
        "trojan": _build_trojan_outbound,
        "shadowsocks": _build_shadowsocks_outbound,
    }
    builder = builders.get(node.protocol)
    if builder is None:
        raise ValueError(f"Unsupported protocol: {node.protocol}")
    return builder(node)


def _build_vless_outbound(node: ParsedNode) -> Dict[str, Any]:
    if node.network == "xhttp":
        raise ValueError(
            "xhttp transport is not supported by xray-core. "
            "Switch to sing-box kernel or use a different node."
        )
    user: Dict[str, Any] = {"id": node.uuid, "encryption": "none"}
    if node.flow:
        user["flow"] = node.flow
    out: Dict[str, Any] = {
        "tag": "proxy",
        "protocol": "vless",
        "settings": {"vnext": [{"address": node.host, "port": node.port, "users": [user]}]},
        "streamSettings": _build_stream_settings(node),
    }
    return out


def _build_vmess_outbound(node: ParsedNode) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "tag": "proxy",
        "protocol": "vmess",
        "settings": {
            "vnext": [{
                "address": node.host,
                "port": node.port,
                "users": [{"id": node.uuid, "alterId": node.alter_id, "security": node.vmess_security or "auto"}],
            }]
        },
        "streamSettings": _build_stream_settings(node),
    }
    return out


def _build_trojan_outbound(node: ParsedNode) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "tag": "proxy",
        "protocol": "trojan",
        "settings": {
            "servers": [{"address": node.host, "port": node.port, "password": node.password}]
        },
        "streamSettings": _build_stream_settings(node),
    }
    return out


def _build_shadowsocks_outbound(node: ParsedNode) -> Dict[str, Any]:
    return {
        "tag": "proxy",
        "protocol": "shadowsocks",
        "settings": {
            "servers": [{
                "address": node.host,
                "port": node.port,
                "method": node.ss_method,
                "password": node.password,
            }]
        },
    }


# ── Stream settings ────────────────────────────────────────────────────────────

def _build_stream_settings(node: ParsedNode) -> Dict[str, Any]:
    ss: Dict[str, Any] = {"network": node.network or "tcp"}

    if node.security in ("tls", "reality"):
        ss["security"] = node.security
        if node.security == "reality":
            ss["realitySettings"] = _build_reality_settings(node)
        else:
            ss["tlsSettings"] = _build_tls_settings(node)
    else:
        ss["security"] = "none"

    transport = _build_transport(node)
    if transport:
        ss.update(transport)

    return ss


def _build_tls_settings(node: ParsedNode) -> Dict[str, Any]:
    tls: Dict[str, Any] = {"serverName": node.sni or node.host}
    if node.fingerprint:
        tls["fingerprint"] = node.fingerprint
    return tls


def _build_reality_settings(node: ParsedNode) -> Dict[str, Any]:
    rs: Dict[str, Any] = {
        "serverName": node.sni or node.host,
        "publicKey": node.reality_pbk,
        "shortId": node.reality_sid,
    }
    if node.fingerprint:
        rs["fingerprint"] = node.fingerprint
    return rs


def _build_transport(node: ParsedNode) -> Dict[str, Any]:
    if node.network == "ws":
        ws: Dict[str, Any] = {"wsSettings": {"path": node.ws_path or "/"}}
        if node.ws_host:
            ws["wsSettings"]["headers"] = {"Host": node.ws_host}
        return ws
    if node.network == "grpc":
        return {"grpcSettings": {"serviceName": node.grpc_service}}
    return {}


# ── Routing ────────────────────────────────────────────────────────────────────

def _build_routing(settings: ConfigSettings) -> Dict[str, Any]:
    rules: List[Dict[str, Any]] = []

    ip_list: List[str] = []
    for code in settings.geo_direct_ip:
        if code == "private":
            ip_list.append("private")
        else:
            ip_list.append(f"geoip:{code}")
    if ip_list:
        rules.append({"type": "field", "ip": ip_list, "outboundTag": "direct"})

    if settings.geo_direct_site:
        domain_list = [f"geosite:{code}" for code in settings.geo_direct_site]
        rules.append({"type": "field", "domain": domain_list, "outboundTag": "direct"})

    return {
        "domainStrategy": "IPIfNonMatch",
        "rules": rules,
    }
