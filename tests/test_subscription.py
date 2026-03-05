import base64
import pytest
from unittest.mock import patch, MagicMock
from src.subscription import fetch_subscription, decode_subscription
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


class TestFetchSubscription:
    def test_successful_fetch(self):
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
