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
    rule_set_dir="/etc/sing-box",
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
        assert "172.19.0.1/30" in tun["address"]
        assert tun["auto_route"] is False
        assert "inet4_address" not in tun
        assert "sniff" not in tun

    def test_tun_mtu_is_1400(self):
        cfg = generate_config(make_vless_reality(), DEFAULT_SETTINGS)
        tun = next(i for i in cfg["inbounds"] if i["type"] == "tun")
        assert tun["mtu"] == 1400

    def test_tun_default_stack_is_mixed(self):
        cfg = generate_config(make_vless_reality(), DEFAULT_SETTINGS)
        tun = next(i for i in cfg["inbounds"] if i["type"] == "tun")
        assert tun["stack"] == "mixed"

    def test_tun_stack_configurable(self):
        s = ConfigSettings(tun_stack="gvisor")
        cfg = generate_config(make_vless_reality(), s)
        tun = next(i for i in cfg["inbounds"] if i["type"] == "tun")
        assert tun["stack"] == "gvisor"

    def test_tun_gso_absent_by_default(self):
        cfg = generate_config(make_vless_reality(), DEFAULT_SETTINGS)
        tun = next(i for i in cfg["inbounds"] if i["type"] == "tun")
        assert "gso" not in tun

    def test_tun_gso_present_when_enabled(self):
        s = ConfigSettings(tun_gso=True)
        cfg = generate_config(make_vless_reality(), s)
        tun = next(i for i in cfg["inbounds"] if i["type"] == "tun")
        assert tun["gso"] is True
        assert tun["gso_max_size"] == 65536

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
    def test_sniff_rule_is_first(self):
        cfg = generate_config(make_vless_reality(), DEFAULT_SETTINGS)
        rules = cfg["route"]["rules"]
        assert rules[0]["action"] == "sniff"

    def test_sniff_rule_has_timeout(self):
        cfg = generate_config(make_vless_reality(), DEFAULT_SETTINGS)
        assert cfg["route"]["rules"][0]["timeout"] == "300ms"

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
        rule_set_rules = [r for r in rules if "rule_set" in r and r.get("outbound") == "direct"]
        all_tags = [tag for r in rule_set_rules for tag in r["rule_set"]]
        assert "geoip-ru" in all_tags

    def test_geo_site_direct_rules(self):
        cfg = generate_config(make_vless_reality(), DEFAULT_SETTINGS)
        rules = cfg["route"]["rules"]
        rule_set_rules = [r for r in rules if "rule_set" in r and r.get("outbound") == "direct"]
        all_tags = [tag for r in rule_set_rules for tag in r["rule_set"]]
        assert "geosite-ru" in all_tags

    def test_route_has_rule_set_definitions(self):
        cfg = generate_config(make_vless_reality(), DEFAULT_SETTINGS)
        rule_set = cfg["route"]["rule_set"]
        tags = [rs["tag"] for rs in rule_set]
        assert "geoip-ru" in tags
        assert "geosite-ru" in tags

    def test_rule_set_paths_use_srs_format(self):
        cfg = generate_config(make_vless_reality(), DEFAULT_SETTINGS)
        for rs in cfg["route"]["rule_set"]:
            assert rs["path"].endswith(".srs"), f"Expected .srs path, got: {rs['path']}"
            assert rs["format"] == "binary"
            assert rs["type"] == "local"

    def test_route_has_default_domain_resolver(self):
        cfg = generate_config(make_vless_reality(), DEFAULT_SETTINGS)
        assert cfg["route"]["default_domain_resolver"] == "local"

    def test_route_no_geoip_geosite_sections(self):
        cfg = generate_config(make_vless_reality(), DEFAULT_SETTINGS)
        assert "geoip" not in cfg["route"]
        assert "geosite" not in cfg["route"]

    def test_rule_set_path_format(self):
        cfg = generate_config(make_vless_reality(), DEFAULT_SETTINGS)
        rs = next(r for r in cfg["route"]["rule_set"] if r["tag"] == "geoip-ru")
        assert rs["path"] == "/etc/sing-box/geoip-ru.srs"


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

    def test_local_server_uses_local_type(self):
        cfg = generate_config(make_vless_reality(), DEFAULT_SETTINGS)
        local = next(s for s in cfg["dns"]["servers"] if s["tag"] == "local")
        assert local["type"] == "local"
        assert "server" not in local

    def test_dns_final_is_remote(self):
        cfg = generate_config(make_vless_reality(), DEFAULT_SETTINGS)
        assert cfg["dns"]["final"] == "remote"

    def test_dns_rule_uses_rule_set_not_geosite(self):
        cfg = generate_config(make_vless_reality(), DEFAULT_SETTINGS)
        for rule in cfg["dns"]["rules"]:
            assert "geosite" not in rule, "geosite removed in sing-box 1.12, use rule_set"

    def test_dns_rule_has_action_route(self):
        cfg = generate_config(make_vless_reality(), DEFAULT_SETTINGS)
        rules = cfg["dns"]["rules"]
        assert len(rules) > 0
        for rule in rules:
            assert rule.get("action") == "route", "DNS rule action is required in sing-box 1.11+"

    def test_dns_rule_targets_local_server(self):
        cfg = generate_config(make_vless_reality(), DEFAULT_SETTINGS)
        rules = cfg["dns"]["rules"]
        local_rule = next((r for r in rules if r.get("server") == "local"), None)
        assert local_rule is not None

    def test_dns_rule_uses_rule_set_for_geosite(self):
        cfg = generate_config(make_vless_reality(), DEFAULT_SETTINGS)
        rules = cfg["dns"]["rules"]
        rule_set_rules = [r for r in rules if "rule_set" in r]
        all_tags = [tag for r in rule_set_rules for tag in r["rule_set"]]
        assert "geosite-ru" in all_tags


def make_shadowsocks() -> ParsedNode:
    return ParsedNode(
        protocol="shadowsocks", host="ss.example.com", port=8388,
        name="SS-1", ss_method="chacha20-ietf-poly1305", password="mypass",
        security="none",
    )

def make_vless_xhttp() -> ParsedNode:
    return ParsedNode(
        protocol="vless", host="xh.example.com", port=443, name="XHTTP-1",
        uuid="test-uuid", security="tls", network="xhttp",
        sni="xh.example.com", fingerprint="chrome",
        ws_path="/api", ws_host="xh.example.com",
        xhttp_mode="stream-one",
        xhttp_extra={"noSSEHeader": True},
    )

def make_vless_xhttp_basic() -> ParsedNode:
    return ParsedNode(
        protocol="vless", host="xh.example.com", port=443, name="XHTTP-Basic",
        uuid="test-uuid", security="reality", network="xhttp",
        reality_pbk="PK", reality_sid="ab12",
        ws_path="/", ws_host="",
    )


class TestDnsCache:
    def test_dns_cache_enabled(self):
        cfg = generate_config(make_vless_reality(), DEFAULT_SETTINGS)
        assert cfg["dns"]["cache"] is True


class TestMultiplex:
    def _mux_settings(self, protocol: str = "h2mux") -> ConfigSettings:
        return ConfigSettings(
            tun_interface="tun0",
            tun_address="172.19.0.1/30",
            geo_direct_ip=["private"],
            geo_direct_site=[],
            rule_set_dir="/etc/sing-box",
            multiplex_protocol=protocol,
        )

    def test_multiplex_added_for_tcp(self):
        cfg = generate_config(make_vless_reality(), self._mux_settings())
        assert cfg["outbounds"][0]["multiplex"]["enabled"] is True
        assert cfg["outbounds"][0]["multiplex"]["protocol"] == "h2mux"

    def test_multiplex_protocol_values(self):
        for proto in ("smux", "yamux", "h2mux"):
            cfg = generate_config(make_vless_reality(), self._mux_settings(proto))
            assert cfg["outbounds"][0]["multiplex"]["protocol"] == proto

    def test_multiplex_not_added_for_grpc(self):
        node = ParsedNode(
            protocol="vless", host="g.example.com", port=443,
            uuid="u", security="tls", network="grpc", grpc_service="svc",
        )
        cfg = generate_config(node, self._mux_settings())
        assert "multiplex" not in cfg["outbounds"][0]

    def test_multiplex_not_added_for_xhttp(self):
        cfg = generate_config(make_vless_xhttp(), self._mux_settings())
        assert "multiplex" not in cfg["outbounds"][0]

    def test_multiplex_not_added_for_shadowsocks(self):
        cfg = generate_config(make_shadowsocks(), self._mux_settings())
        assert "multiplex" not in cfg["outbounds"][0]

    def test_multiplex_absent_when_protocol_empty(self):
        cfg = generate_config(make_vless_reality(), DEFAULT_SETTINGS)
        assert "multiplex" not in cfg["outbounds"][0]

    def test_multiplex_max_connections_default(self):
        cfg = generate_config(make_vless_reality(), self._mux_settings())
        assert cfg["outbounds"][0]["multiplex"]["max_connections"] == 4

    def test_multiplex_max_connections_custom(self):
        s = ConfigSettings(multiplex_protocol="h2mux", multiplex_max_connections=8)
        cfg = generate_config(make_vless_reality(), s)
        assert cfg["outbounds"][0]["multiplex"]["max_connections"] == 8

    def test_multiplex_added_for_ws(self):
        cfg = generate_config(make_vmess_ws(), self._mux_settings())
        assert "multiplex" in cfg["outbounds"][0]


class TestFlowExclusion:
    def test_flow_excluded_for_grpc(self):
        node = ParsedNode(
            protocol="vless", host="xh.example.com", port=443,
            uuid="u", security="tls", network="grpc",
            grpc_service="myService", flow="xtls-rprx-vision",
        )
        cfg = generate_config(node, DEFAULT_SETTINGS)
        assert "flow" not in cfg["outbounds"][0]

    def test_flow_excluded_for_xhttp(self):
        node = ParsedNode(
            protocol="vless", host="xh.example.com", port=443,
            uuid="u", security="tls", network="xhttp",
            ws_path="/", flow="xtls-rprx-vision",
        )
        cfg = generate_config(node, DEFAULT_SETTINGS)
        assert "flow" not in cfg["outbounds"][0]


class TestShadowsocksOutbound:
    def test_outbound_type(self):
        cfg = generate_config(make_shadowsocks(), DEFAULT_SETTINGS)
        assert cfg["outbounds"][0]["type"] == "shadowsocks"

    def test_method_and_password(self):
        cfg = generate_config(make_shadowsocks(), DEFAULT_SETTINGS)
        proxy = cfg["outbounds"][0]
        assert proxy["method"] == "chacha20-ietf-poly1305"
        assert proxy["password"] == "mypass"

    def test_no_tls_block(self):
        cfg = generate_config(make_shadowsocks(), DEFAULT_SETTINGS)
        assert "tls" not in cfg["outbounds"][0]

    def test_no_transport_block(self):
        cfg = generate_config(make_shadowsocks(), DEFAULT_SETTINGS)
        assert "transport" not in cfg["outbounds"][0]

    def test_server_and_port(self):
        cfg = generate_config(make_shadowsocks(), DEFAULT_SETTINGS)
        proxy = cfg["outbounds"][0]
        assert proxy["server"] == "ss.example.com"
        assert proxy["server_port"] == 8388


class TestXhttpTransport:
    def test_transport_type_is_xhttp(self):
        cfg = generate_config(make_vless_xhttp(), DEFAULT_SETTINGS)
        assert cfg["outbounds"][0]["transport"]["type"] == "xhttp"

    def test_path(self):
        cfg = generate_config(make_vless_xhttp(), DEFAULT_SETTINGS)
        assert cfg["outbounds"][0]["transport"]["path"] == "/api"

    def test_host_is_list(self):
        cfg = generate_config(make_vless_xhttp(), DEFAULT_SETTINGS)
        assert cfg["outbounds"][0]["transport"]["host"] == ["xh.example.com"]

    def test_mode_included_when_set(self):
        cfg = generate_config(make_vless_xhttp(), DEFAULT_SETTINGS)
        assert cfg["outbounds"][0]["transport"]["mode"] == "stream-one"

    def test_extra_included_when_set(self):
        cfg = generate_config(make_vless_xhttp(), DEFAULT_SETTINGS)
        assert cfg["outbounds"][0]["transport"]["extra"] == {"noSSEHeader": True}

    def test_mode_omitted_when_empty(self):
        cfg = generate_config(make_vless_xhttp_basic(), DEFAULT_SETTINGS)
        assert "mode" not in cfg["outbounds"][0]["transport"]

    def test_extra_omitted_when_empty(self):
        cfg = generate_config(make_vless_xhttp_basic(), DEFAULT_SETTINGS)
        assert "extra" not in cfg["outbounds"][0]["transport"]

    def test_host_empty_string_omits_host(self):
        cfg = generate_config(make_vless_xhttp_basic(), DEFAULT_SETTINGS)
        assert "host" not in cfg["outbounds"][0]["transport"]

    def test_host_multi_value_split_into_list(self):
        node = ParsedNode(
            protocol="vless", host="xh.example.com", port=443, name="X",
            uuid="u", security="tls", network="xhttp",
            ws_path="/", ws_host="a.example.com, b.example.com",
        )
        cfg = generate_config(node, DEFAULT_SETTINGS)
        assert cfg["outbounds"][0]["transport"]["host"] == ["a.example.com", "b.example.com"]

    def test_method_omitted_when_not_set(self):
        cfg = generate_config(make_vless_xhttp_basic(), DEFAULT_SETTINGS)
        assert "method" not in cfg["outbounds"][0]["transport"]

    def test_method_set_when_explicit(self):
        node = ParsedNode(
            protocol="vless", host="xh.example.com", port=443, name="XHTTP-POST",
            uuid="test-uuid", security="tls", network="xhttp",
            sni="xh.example.com", fingerprint="chrome",
            ws_path="/upload", xhttp_method="POST",
        )
        cfg = generate_config(node, DEFAULT_SETTINGS)
        assert cfg["outbounds"][0]["transport"]["method"] == "POST"
