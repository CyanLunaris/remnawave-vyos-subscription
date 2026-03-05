import json
import pytest
from src.uri_parser import ParsedNode
from src.config_generator import generate_config, ConfigSettings


def make_vless_reality() -> ParsedNode:
    return ParsedNode(
        protocol="vless", host="nl1.example.com", port=443, name="NL-1",
        uuid="test-uuid", security="reality", network="tcp",
        flow="xtls-rprx-vision", reality_pbk="PUBLIC_KEY",
        reality_sid="abcdef", sni="www.microsoft.com", fingerprint="chrome",
    )

def make_vmess_ws() -> ParsedNode:
    return ParsedNode(
        protocol="vmess", host="vmess.example.com", port=443, name="VMess-WS",
        uuid="vmess-uuid", security="tls", network="ws",
        ws_path="/ws", ws_host="vmess.example.com", sni="vmess.example.com",
        fingerprint="chrome", alter_id=0, vmess_security="auto",
    )

def make_trojan() -> ParsedNode:
    return ParsedNode(
        protocol="trojan", host="tr.example.com", port=443, name="TR-1",
        password="mypass", security="tls", sni="tr.example.com",
    )


DEFAULT_SETTINGS = ConfigSettings(
    tun_interface="tun0",
    tun_address="172.19.0.1/30",
    geo_direct_ip=["private", "ru"],
    geo_direct_site=["ru"],
    geoip_path="/etc/sing-box/geoip.db",
    geosite_path="/etc/sing-box/geosite.db",
)


class TestConfigStructure:
    def test_has_required_top_level_keys(self):
        cfg = generate_config(make_vless_reality(), DEFAULT_SETTINGS)
        assert "inbounds" in cfg
        assert "outbounds" in cfg
        assert "route" in cfg

    def test_tun_inbound_present(self):
        cfg = generate_config(make_vless_reality(), DEFAULT_SETTINGS)
        tun = next(i for i in cfg["inbounds"] if i["type"] == "tun")
        assert tun["interface_name"] == "tun0"
        assert tun["inet4_address"] == "172.19.0.1/30"
        assert tun["auto_route"] is False

    def test_has_direct_outbound(self):
        cfg = generate_config(make_vless_reality(), DEFAULT_SETTINGS)
        tags = [o["tag"] for o in cfg["outbounds"]]
        assert "direct" in tags
        assert "dns-out" not in tags  # removed in sing-box 1.13+

    def test_proxy_outbound_is_first(self):
        cfg = generate_config(make_vless_reality(), DEFAULT_SETTINGS)
        assert cfg["outbounds"][0]["tag"] == "proxy"

    def test_route_final_is_proxy(self):
        cfg = generate_config(make_vless_reality(), DEFAULT_SETTINGS)
        assert cfg["route"]["final"] == "proxy"


class TestVlessRealityOutbound:
    def test_outbound_type(self):
        cfg = generate_config(make_vless_reality(), DEFAULT_SETTINGS)
        proxy = cfg["outbounds"][0]
        assert proxy["type"] == "vless"

    def test_server_and_port(self):
        cfg = generate_config(make_vless_reality(), DEFAULT_SETTINGS)
        proxy = cfg["outbounds"][0]
        assert proxy["server"] == "nl1.example.com"
        assert proxy["server_port"] == 443

    def test_reality_tls(self):
        cfg = generate_config(make_vless_reality(), DEFAULT_SETTINGS)
        proxy = cfg["outbounds"][0]
        tls = proxy["tls"]
        assert tls["enabled"] is True
        assert tls["reality"]["enabled"] is True
        assert tls["reality"]["public_key"] == "PUBLIC_KEY"
        assert tls["reality"]["short_id"] == "abcdef"
        assert tls["server_name"] == "www.microsoft.com"

    def test_flow(self):
        cfg = generate_config(make_vless_reality(), DEFAULT_SETTINGS)
        assert cfg["outbounds"][0]["flow"] == "xtls-rprx-vision"


class TestVmessWsOutbound:
    def test_outbound_type(self):
        cfg = generate_config(make_vmess_ws(), DEFAULT_SETTINGS)
        assert cfg["outbounds"][0]["type"] == "vmess"

    def test_ws_transport(self):
        cfg = generate_config(make_vmess_ws(), DEFAULT_SETTINGS)
        transport = cfg["outbounds"][0]["transport"]
        assert transport["type"] == "ws"
        assert transport["path"] == "/ws"


class TestTrojanOutbound:
    def test_outbound_type(self):
        cfg = generate_config(make_trojan(), DEFAULT_SETTINGS)
        assert cfg["outbounds"][0]["type"] == "trojan"

    def test_password(self):
        cfg = generate_config(make_trojan(), DEFAULT_SETTINGS)
        assert cfg["outbounds"][0]["password"] == "mypass"


class TestRouting:
    def test_dns_rule_uses_hijack_action(self):
        cfg = generate_config(make_vless_reality(), DEFAULT_SETTINGS)
        rules = cfg["route"]["rules"]
        dns_rule = next(r for r in rules if r.get("protocol") == "dns")
        assert dns_rule["action"] == "hijack-dns"
        assert "outbound" not in dns_rule

    def test_private_ip_goes_direct(self):
        cfg = generate_config(make_vless_reality(), DEFAULT_SETTINGS)
        rules = cfg["route"]["rules"]
        private_rule = next(r for r in rules if r.get("ip_is_private"))
        assert private_rule["outbound"] == "direct"

    def test_geo_ip_direct_rules(self):
        cfg = generate_config(make_vless_reality(), DEFAULT_SETTINGS)
        rules = cfg["route"]["rules"]
        geo_ip_rules = [r for r in rules if "geoip" in r]
        geoip_codes = [code for r in geo_ip_rules for code in r["geoip"]]
        assert "ru" in geoip_codes

    def test_geo_site_direct_rules(self):
        cfg = generate_config(make_vless_reality(), DEFAULT_SETTINGS)
        rules = cfg["route"]["rules"]
        geo_site_rules = [r for r in rules if "geosite" in r]
        geosite_codes = [code for r in geo_site_rules for code in r["geosite"]]
        assert "ru" in geosite_codes

    def test_geoip_db_path(self):
        cfg = generate_config(make_vless_reality(), DEFAULT_SETTINGS)
        assert cfg["route"]["geoip"]["path"] == "/etc/sing-box/geoip.db"


class TestDns:
    def test_remote_server_uses_type_field(self):
        cfg = generate_config(make_vless_reality(), DEFAULT_SETTINGS)
        remote = next(s for s in cfg["dns"]["servers"] if s["tag"] == "remote")
        assert remote["type"] == "https"
        assert "address" not in remote

    def test_remote_server_field(self):
        s = ConfigSettings(dns_server="8.8.8.8")
        cfg = generate_config(make_vless_reality(), s)
        remote = next(srv for srv in cfg["dns"]["servers"] if srv["tag"] == "remote")
        assert remote["server"] == "8.8.8.8"

    def test_local_server_uses_udp_type(self):
        cfg = generate_config(make_vless_reality(), DEFAULT_SETTINGS)
        local = next(s for s in cfg["dns"]["servers"] if s["tag"] == "local")
        assert local["type"] == "udp"
        assert "address" not in local

    def test_dns_final_is_remote(self):
        cfg = generate_config(make_vless_reality(), DEFAULT_SETTINGS)
        assert cfg["dns"]["final"] == "remote"
