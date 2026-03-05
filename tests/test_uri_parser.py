import pytest
from src.uri_parser import parse_uri, ParsedNode

class TestVlessParser:
    def test_vless_reality_basic(self):
        uri = (
            "vless://9f4f8c7d-4a7a-4f8e-8f4a-7f4a8e7f4a8e@nl1.example.com:443"
            "?security=reality&encryption=none&pbk=PUBLIC_KEY_BASE64"
            "&sid=abcdef12&sni=www.microsoft.com&flow=xtls-rprx-vision"
            "&type=tcp&fp=chrome#NL-1"
        )
        node = parse_uri(uri)
        assert node.protocol == "vless"
        assert node.host == "nl1.example.com"
        assert node.port == 443
        assert node.uuid == "9f4f8c7d-4a7a-4f8e-8f4a-7f4a8e7f4a8e"
        assert node.security == "reality"
        assert node.flow == "xtls-rprx-vision"
        assert node.reality_pbk == "PUBLIC_KEY_BASE64"
        assert node.reality_sid == "abcdef12"
        assert node.sni == "www.microsoft.com"
        assert node.fingerprint == "chrome"
        assert node.network == "tcp"
        assert node.name == "NL-1"

    def test_vless_tls(self):
        uri = (
            "vless://uuid123@host.example.com:8443"
            "?security=tls&sni=host.example.com&type=ws&path=%2Fws#WS-TLS"
        )
        node = parse_uri(uri)
        assert node.protocol == "vless"
        assert node.security == "tls"
        assert node.network == "ws"
        assert node.ws_path == "/ws"
        assert node.name == "WS-TLS"

    def test_vless_missing_security_defaults_to_none(self):
        uri = "vless://uuid@host.com:443?encryption=none#test"
        node = parse_uri(uri)
        assert node.security == "none"


class TestVmessParser:
    def test_vmess_basic(self):
        import base64, json
        payload = {
            "v": "2", "ps": "VMess-Test", "add": "vmess.example.com",
            "port": "443", "id": "vmess-uuid", "aid": "0",
            "scy": "auto", "net": "tcp", "type": "none",
            "host": "", "path": "", "tls": "tls", "sni": "vmess.example.com",
            "alpn": "", "fp": "chrome"
        }
        encoded = base64.b64encode(json.dumps(payload).encode()).decode()
        uri = f"vmess://{encoded}"
        node = parse_uri(uri)
        assert node.protocol == "vmess"
        assert node.host == "vmess.example.com"
        assert node.port == 443
        assert node.uuid == "vmess-uuid"
        assert node.security == "tls"
        assert node.name == "VMess-Test"

    def test_vmess_ws(self):
        import base64, json
        payload = {
            "v": "2", "ps": "VMess-WS", "add": "ws.example.com",
            "port": "80", "id": "ws-uuid", "aid": "0",
            "scy": "auto", "net": "ws", "type": "none",
            "host": "ws.example.com", "path": "/path", "tls": "",
            "sni": "", "alpn": "", "fp": ""
        }
        encoded = base64.b64encode(json.dumps(payload).encode()).decode()
        uri = f"vmess://{encoded}"
        node = parse_uri(uri)
        assert node.network == "ws"
        assert node.ws_path == "/path"
        assert node.ws_host == "ws.example.com"
        assert node.security == "none"


class TestTrojanParser:
    def test_trojan_basic(self):
        uri = "trojan://mypassword@tr.example.com:443?sni=tr.example.com#TR-1"
        node = parse_uri(uri)
        assert node.protocol == "trojan"
        assert node.host == "tr.example.com"
        assert node.port == 443
        assert node.password == "mypassword"
        assert node.sni == "tr.example.com"
        assert node.name == "TR-1"

    def test_trojan_no_sni(self):
        uri = "trojan://pass@host.com:443#no-sni"
        node = parse_uri(uri)
        assert node.sni == "host.com"  # falls back to host


class TestParseUriErrors:
    def test_unknown_scheme_returns_none(self):
        assert parse_uri("ss://something") is None

    def test_empty_string_returns_none(self):
        assert parse_uri("") is None

    def test_malformed_vmess_returns_none(self):
        assert parse_uri("vmess://not-base64!!!") is None
