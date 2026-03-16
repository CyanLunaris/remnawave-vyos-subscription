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
        assert parse_uri("ssr://something") is None

    def test_empty_string_returns_none(self):
        assert parse_uri("") is None

    def test_malformed_vmess_returns_none(self):
        assert parse_uri("vmess://not-base64!!!") is None


class TestShadowsocksParser:
    def test_ss_sip002_basic(self):
        import base64
        userinfo = base64.urlsafe_b64encode(b"chacha20-ietf-poly1305:mypassword").decode().rstrip("=")
        uri = f"ss://{userinfo}@ss.example.com:8388#SS-1"
        node = parse_uri(uri)
        assert node is not None
        assert node.protocol == "shadowsocks"
        assert node.host == "ss.example.com"
        assert node.port == 8388
        assert node.ss_method == "chacha20-ietf-poly1305"
        assert node.password == "mypassword"
        assert node.name == "SS-1"

    def test_ss_plain_userinfo(self):
        """Some servers emit method:password without base64."""
        uri = "ss://aes-256-gcm:secretpass@host.com:443#plain"
        node = parse_uri(uri)
        assert node is not None
        assert node.ss_method == "aes-256-gcm"
        assert node.password == "secretpass"

    def test_ss_no_name(self):
        import base64
        userinfo = base64.urlsafe_b64encode(b"chacha20-ietf-poly1305:pw").decode().rstrip("=")
        uri = f"ss://{userinfo}@host.com:1080"
        node = parse_uri(uri)
        assert node is not None
        assert node.name == ""

    def test_ss_malformed_returns_none(self):
        assert parse_uri("ss://notvalid") is None

    def test_unknown_scheme_still_none(self):
        assert parse_uri("ssr://something") is None

    def test_ss_b64_unknown_method_returns_none(self):
        import base64
        userinfo = base64.urlsafe_b64encode(b"xchacha20:mypassword").decode().rstrip("=")
        uri = f"ss://{userinfo}@host.com:1080"
        assert parse_uri(uri) is None


class TestXhttpUriParsing:
    def test_vless_xhttp_basic(self):
        uri = (
            "vless://uuid-1234@xh.example.com:443"
            "?security=tls&sni=xh.example.com&type=xhttp"
            "&path=%2Fapi&host=xh.example.com#XHTTP-1"
        )
        node = parse_uri(uri)
        assert node is not None
        assert node.network == "xhttp"
        assert node.ws_path == "/api"
        assert node.ws_host == "xh.example.com"
        assert node.xhttp_mode == ""
        assert node.xhttp_extra == {}

    def test_vless_xhttp_with_mode(self):
        uri = (
            "vless://uuid@host.com:443"
            "?security=reality&pbk=PK&sid=ab12&type=xhttp"
            "&path=%2F&xhttpMode=stream-one#XHTTP-Mode"
        )
        node = parse_uri(uri)
        assert node.xhttp_mode == "stream-one"

    def test_vless_xhttp_with_extra(self):
        import json, urllib.parse
        extra = {"noSSEHeader": True}
        uri = (
            "vless://uuid@host.com:443"
            f"?type=xhttp&path=%2F&extra={urllib.parse.quote(json.dumps(extra))}#XHTTP-Extra"
        )
        node = parse_uri(uri)
        assert node.xhttp_extra == {"noSSEHeader": True}

    def test_vless_xhttp_bad_extra_ignored(self):
        uri = "vless://uuid@host.com:443?type=xhttp&extra=notjson#X"
        node = parse_uri(uri)
        assert node.xhttp_extra == {}

    def test_vless_xhttp_with_method(self):
        uri = "vless://uuid@host.com:443?type=xhttp&path=%2F&xhttpMethod=POST#X"
        node = parse_uri(uri)
        assert node.xhttp_method == "POST"

    def test_vless_xhttp_method_defaults_empty(self):
        uri = "vless://uuid@host.com:443?type=xhttp&path=%2F#X"
        node = parse_uri(uri)
        assert node.xhttp_method == ""
