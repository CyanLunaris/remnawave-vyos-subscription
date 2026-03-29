import pytest
from src.uri_parser import ParsedNode
from src.config_generator import ConfigSettings
from src.xray_config_generator import generate_xray_config


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


def make_shadowsocks() -> ParsedNode:
    return ParsedNode(
        protocol="shadowsocks", host="ss.example.com", port=8388,
        name="SS-1", ss_method="chacha20-ietf-poly1305", password="sspass",
        security="none",
    )


def make_vless_xhttp() -> ParsedNode:
    return ParsedNode(
        protocol="vless", host="xh.example.com", port=443, name="XHTTP",
        uuid="u", security="tls", network="xhttp",
        sni="xh.example.com", fingerprint="chrome",
    )


DEFAULT_SETTINGS = ConfigSettings(
    tun_interface="tun0",
    tun_address="172.19.0.1/30",
    geo_direct_ip=["private", "ru"],
    geo_direct_site=["category-ru"],
    rule_set_dir="/etc/sing-box",
)


class TestConfigStructure:
    def test_has_required_top_level_keys(self):
        cfg = generate_xray_config(make_vless_reality(), DEFAULT_SETTINGS)
        assert "log" in cfg
        assert "inbounds" in cfg
        assert "outbounds" in cfg
        assert "routing" in cfg

    def test_socks_inbound_on_7891(self):
        cfg = generate_xray_config(make_vless_reality(), DEFAULT_SETTINGS)
        inbound = cfg["inbounds"][0]
        assert inbound["protocol"] == "socks"
        assert inbound["port"] == 7891
        assert inbound["listen"] == "127.0.0.1"
        assert inbound["settings"]["udp"] is True

    def test_direct_outbound_present(self):
        cfg = generate_xray_config(make_vless_reality(), DEFAULT_SETTINGS)
        tags = [o["tag"] for o in cfg["outbounds"]]
        assert "direct" in tags

    def test_proxy_outbound_is_first(self):
        cfg = generate_xray_config(make_vless_reality(), DEFAULT_SETTINGS)
        assert cfg["outbounds"][0]["tag"] == "proxy"

    def test_routing_domain_strategy(self):
        cfg = generate_xray_config(make_vless_reality(), DEFAULT_SETTINGS)
        assert cfg["routing"]["domainStrategy"] == "IPIfNonMatch"


class TestVlessRealityOutbound:
    def test_protocol(self):
        cfg = generate_xray_config(make_vless_reality(), DEFAULT_SETTINGS)
        assert cfg["outbounds"][0]["protocol"] == "vless"

    def test_server_address_and_port(self):
        cfg = generate_xray_config(make_vless_reality(), DEFAULT_SETTINGS)
        vnext = cfg["outbounds"][0]["settings"]["vnext"][0]
        assert vnext["address"] == "nl1.example.com"
        assert vnext["port"] == 443

    def test_uuid(self):
        cfg = generate_xray_config(make_vless_reality(), DEFAULT_SETTINGS)
        user = cfg["outbounds"][0]["settings"]["vnext"][0]["users"][0]
        assert user["id"] == "test-uuid"

    def test_flow_present_for_xtls(self):
        cfg = generate_xray_config(make_vless_reality(), DEFAULT_SETTINGS)
        user = cfg["outbounds"][0]["settings"]["vnext"][0]["users"][0]
        assert user["flow"] == "xtls-rprx-vision"

    def test_flow_absent_when_empty(self):
        node = ParsedNode(
            protocol="vless", host="h.com", port=443, uuid="u",
            security="tls", network="tcp", sni="h.com",
        )
        cfg = generate_xray_config(node, DEFAULT_SETTINGS)
        user = cfg["outbounds"][0]["settings"]["vnext"][0]["users"][0]
        assert "flow" not in user

    def test_reality_stream_settings(self):
        cfg = generate_xray_config(make_vless_reality(), DEFAULT_SETTINGS)
        ss = cfg["outbounds"][0]["streamSettings"]
        assert ss["security"] == "reality"
        rs = ss["realitySettings"]
        assert rs["publicKey"] == "PUBLIC_KEY"
        assert rs["shortId"] == "abcdef"
        assert rs["serverName"] == "www.microsoft.com"
        assert rs["fingerprint"] == "chrome"
        assert "tlsSettings" not in ss

    def test_tls_settings_for_tls_security(self):
        node = ParsedNode(
            protocol="vless", host="h.com", port=443, uuid="u",
            security="tls", network="tcp", sni="h.com", fingerprint="firefox",
        )
        cfg = generate_xray_config(node, DEFAULT_SETTINGS)
        ss = cfg["outbounds"][0]["streamSettings"]
        assert ss["security"] == "tls"
        tls = ss["tlsSettings"]
        assert tls["serverName"] == "h.com"
        assert tls["fingerprint"] == "firefox"
        assert "realitySettings" not in ss


class TestVmessWsOutbound:
    def test_protocol(self):
        cfg = generate_xray_config(make_vmess_ws(), DEFAULT_SETTINGS)
        assert cfg["outbounds"][0]["protocol"] == "vmess"

    def test_ws_transport(self):
        cfg = generate_xray_config(make_vmess_ws(), DEFAULT_SETTINGS)
        ss = cfg["outbounds"][0]["streamSettings"]
        assert ss["network"] == "ws"
        assert ss["wsSettings"]["path"] == "/ws"
        assert ss["wsSettings"]["headers"]["Host"] == "vmess.example.com"


class TestTrojanOutbound:
    def test_protocol(self):
        cfg = generate_xray_config(make_trojan(), DEFAULT_SETTINGS)
        assert cfg["outbounds"][0]["protocol"] == "trojan"

    def test_password(self):
        cfg = generate_xray_config(make_trojan(), DEFAULT_SETTINGS)
        server = cfg["outbounds"][0]["settings"]["servers"][0]
        assert server["password"] == "mypass"
        assert server["address"] == "tr.example.com"
        assert server["port"] == 443


class TestShadowsocksOutbound:
    def test_protocol(self):
        cfg = generate_xray_config(make_shadowsocks(), DEFAULT_SETTINGS)
        assert cfg["outbounds"][0]["protocol"] == "shadowsocks"

    def test_method_and_password(self):
        cfg = generate_xray_config(make_shadowsocks(), DEFAULT_SETTINGS)
        server = cfg["outbounds"][0]["settings"]["servers"][0]
        assert server["method"] == "chacha20-ietf-poly1305"
        assert server["password"] == "sspass"

    def test_no_stream_settings(self):
        cfg = generate_xray_config(make_shadowsocks(), DEFAULT_SETTINGS)
        assert "streamSettings" not in cfg["outbounds"][0]


class TestXhttpRaisesValueError:
    def test_xhttp_raises(self):
        with pytest.raises(ValueError, match="xhttp"):
            generate_xray_config(make_vless_xhttp(), DEFAULT_SETTINGS)


class TestRouting:
    def test_private_ip_direct(self):
        cfg = generate_xray_config(make_vless_reality(), DEFAULT_SETTINGS)
        rules = cfg["routing"]["rules"]
        ip_rule = next(r for r in rules if "ip" in r)
        assert "private" in ip_rule["ip"]
        assert ip_rule["outboundTag"] == "direct"

    def test_geoip_ru_in_ip_rule(self):
        cfg = generate_xray_config(make_vless_reality(), DEFAULT_SETTINGS)
        rules = cfg["routing"]["rules"]
        ip_rule = next(r for r in rules if "ip" in r)
        assert "geoip:ru" in ip_rule["ip"]

    def test_geosite_domain_rule(self):
        cfg = generate_xray_config(make_vless_reality(), DEFAULT_SETTINGS)
        rules = cfg["routing"]["rules"]
        domain_rule = next(r for r in rules if "domain" in r)
        assert "geosite:category-ru" in domain_rule["domain"]
        assert domain_rule["outboundTag"] == "direct"

    def test_custom_geo_codes(self):
        settings = ConfigSettings(
            geo_direct_ip=["private", "cn"],
            geo_direct_site=["category-cn"],
        )
        cfg = generate_xray_config(make_vless_reality(), settings)
        rules = cfg["routing"]["rules"]
        ip_rule = next(r for r in rules if "ip" in r)
        assert "geoip:cn" in ip_rule["ip"]
        domain_rule = next(r for r in rules if "domain" in r)
        assert "geosite:category-cn" in domain_rule["domain"]

    def test_no_domain_rule_when_geo_site_empty(self):
        settings = ConfigSettings(geo_direct_ip=["private"], geo_direct_site=[])
        cfg = generate_xray_config(make_vless_reality(), settings)
        rules = cfg["routing"]["rules"]
        assert not any("domain" in r for r in rules)
