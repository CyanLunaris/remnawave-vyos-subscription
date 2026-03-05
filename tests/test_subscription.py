import base64
import json
import pytest
from unittest.mock import patch, MagicMock
from src.subscription import fetch_subscription, decode_subscription, USER_AGENT
from src.uri_parser import ParsedNode


SAMPLE_VLESS = (
    "vless://9f4f8c7d-4a7a-4f8e-8f4a-7f4a8e7f4a8e@nl1.example.com:443"
    "?security=reality&pbk=KEY&sid=abc&sni=microsoft.com&flow=xtls-rprx-vision&type=tcp&fp=chrome#NL-1"
)
SAMPLE_TROJAN = "trojan://pass@tr.example.com:443?sni=tr.example.com#TR-1"


class TestDecodeSubscription:
    def test_plain_text_uri_list(self):
        raw = f"{SAMPLE_VLESS}\n{SAMPLE_TROJAN}\n"
        nodes = decode_subscription(raw)
        assert len(nodes) == 2
        assert nodes[0].protocol == "vless"
        assert nodes[1].protocol == "trojan"

    def test_base64_encoded_list(self):
        plain = f"{SAMPLE_VLESS}\n{SAMPLE_TROJAN}"
        encoded = base64.b64encode(plain.encode()).decode()
        nodes = decode_subscription(encoded)
        assert len(nodes) == 2

    def test_skips_unknown_schemes(self):
        raw = f"ss://something\n{SAMPLE_VLESS}\n#comment\n"
        nodes = decode_subscription(raw)
        assert len(nodes) == 1
        assert nodes[0].protocol == "vless"

    def test_empty_response_returns_empty_list(self):
        assert decode_subscription("") == []

    def test_base64_with_padding_issues(self):
        plain = SAMPLE_VLESS
        # Ensure it works regardless of padding
        encoded = base64.b64encode(plain.encode()).decode().rstrip("=")
        nodes = decode_subscription(encoded)
        assert len(nodes) == 1


SINGBOX_RESPONSE = json.dumps({
    "outbounds": [
        {
            "type": "vless",
            "tag": "NL-1",
            "server": "nl1.example.com",
            "server_port": 443,
            "uuid": "9f4f8c7d-4a7a-4f8e-8f4a-7f4a8e7f4a8e",
            "flow": "xtls-rprx-vision",
            "tls": {
                "enabled": True,
                "server_name": "www.microsoft.com",
                "utls": {"enabled": True, "fingerprint": "chrome"},
                "reality": {"enabled": True, "public_key": "PBK123", "short_id": "abc"},
            },
        },
        {
            "type": "trojan",
            "tag": "TR-1",
            "server": "tr.example.com",
            "server_port": 443,
            "password": "mypass",
            "tls": {"enabled": True, "server_name": "tr.example.com"},
        },
        # Dummy "App not supported" node — must be skipped
        {
            "type": "vless",
            "tag": "App not supported",
            "server": "0.0.0.0",
            "server_port": 1,
            "uuid": "00000000-0000-0000-0000-000000000000",
        },
        {"type": "selector", "tag": "proxy", "outbounds": ["NL-1"]},
        {"type": "direct", "tag": "direct"},
    ]
})


class TestDecodeSingboxJson:
    def test_parses_vless_outbound(self):
        nodes = decode_subscription(SINGBOX_RESPONSE)
        vless = next(n for n in nodes if n.protocol == "vless")
        assert vless.host == "nl1.example.com"
        assert vless.port == 443
        assert vless.uuid == "9f4f8c7d-4a7a-4f8e-8f4a-7f4a8e7f4a8e"
        assert vless.flow == "xtls-rprx-vision"
        assert vless.security == "reality"
        assert vless.reality_pbk == "PBK123"
        assert vless.sni == "www.microsoft.com"

    def test_parses_trojan_outbound(self):
        nodes = decode_subscription(SINGBOX_RESPONSE)
        trojan = next(n for n in nodes if n.protocol == "trojan")
        assert trojan.host == "tr.example.com"
        assert trojan.password == "mypass"
        assert trojan.security == "tls"

    def test_skips_selector_and_direct(self):
        nodes = decode_subscription(SINGBOX_RESPONSE)
        types = {n.protocol for n in nodes}
        assert "selector" not in types
        assert "direct" not in types

    def test_skips_dummy_app_not_supported(self):
        nodes = decode_subscription(SINGBOX_RESPONSE)
        assert all(n.host != "0.0.0.0" for n in nodes)
        assert len(nodes) == 2

    def test_node_count(self):
        nodes = decode_subscription(SINGBOX_RESPONSE)
        assert len(nodes) == 2


class TestFetchSubscription:
    def test_uses_sfa_user_agent(self):
        assert "sfa" in USER_AGENT.lower()

    def test_successful_fetch_singbox(self):
        mock_response = MagicMock()
        mock_response.read.return_value = SINGBOX_RESPONSE.encode()
        mock_response.status = 200
        mock_response.__enter__ = lambda s: s
        mock_response.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_response):
            nodes = fetch_subscription("https://panel.example.com/sub/TOKEN")

        assert len(nodes) == 2

    def test_successful_fetch_plain_uri(self):
        mock_response = MagicMock()
        mock_response.read.return_value = SAMPLE_VLESS.encode()
        mock_response.status = 200
        mock_response.__enter__ = lambda s: s
        mock_response.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_response):
            nodes = fetch_subscription("https://panel.example.com/sub/TOKEN")

        assert len(nodes) == 1

    def test_http_error_raises(self):
        import urllib.error
        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("timeout")):
            with pytest.raises(ConnectionError):
                fetch_subscription("https://panel.example.com/sub/TOKEN")

    def test_non_200_raises(self):
        mock_response = MagicMock()
        mock_response.status = 403
        mock_response.__enter__ = lambda s: s
        mock_response.__exit__ = MagicMock(return_value=False)
        with patch("urllib.request.urlopen", return_value=mock_response):
            with pytest.raises(ConnectionError, match="403"):
                fetch_subscription("https://panel.example.com/sub/TOKEN")
