# Remnawave Sync — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a VyOS service that pulls VLESS/VMess/Trojan configs from a Remnawave subscription URL, runs sing-box as a transparent TUN proxy, and auto-rotates nodes on failure.

**Architecture:** Python 3 scripts (stdlib only, no pip required) + systemd service/timer units. `remnawave-sync.py` fetches subscription, parses URIs, generates sing-box `config.json`, manages binary downloads. `remnawave-heartbeat.py` checks connectivity and rotates nodes. sing-box creates `tun0` and handles geo-based routing.

**Tech Stack:** Python 3.9+ (stdlib only), sing-box (downloaded), geoip.db + geosite.db (SagerNet/sing-geoip), systemd, VyOS 1.4+ (Debian 11 base)

---

## Project Structure

```
vyos-remnawave/
  src/
    uri_parser.py        # parse vless://, vmess://, trojan:// URIs
    subscription.py      # fetch + decode subscription
    config_generator.py  # generate sing-box config.json
    binary_manager.py    # download sing-box + geo files
    state_manager.py     # read/write state.json + nodes.json
    sync.py              # main sync orchestrator
    heartbeat.py         # connectivity check + node rotation
  tests/
    test_uri_parser.py
    test_subscription.py
    test_config_generator.py
    test_state_manager.py
    test_heartbeat.py
  systemd/
    sing-box.service
    remnawave-sync.service
    remnawave-sync.timer
    remnawave-heartbeat.service
    remnawave-heartbeat.timer
  install.sh             # installs everything to VyOS
  config.env.example     # example configuration
```

---

### Task 1: Project Scaffolding

**Files:**
- Create: `src/__init__.py` (empty)
- Create: `tests/__init__.py` (empty)
- Create: `config.env.example`

**Step 1: Create directory structure**

```bash
mkdir -p src tests systemd
touch src/__init__.py tests/__init__.py
```

**Step 2: Create `config.env.example`**

```bash
# /etc/remnawave/config.env
SUBSCRIPTION_URL=https://panel.example.com/sub/YOUR_TOKEN_HERE
SYNC_INTERVAL=10min
HEARTBEAT_INTERVAL=30s
HEARTBEAT_HOST=cp.cloudflare.com
HEARTBEAT_FAIL_THRESHOLD=2
HEARTBEAT_TIMEOUT=5

GEO_DIRECT_IP=private,ru
GEO_DIRECT_SITE=ru
TUN_INTERFACE=tun0
TUN_ADDRESS=172.19.0.1/30

XRAY_BIN=/usr/local/bin/sing-box
XRAY_CONFIG=/etc/sing-box/config.json
NODES_FILE=/etc/remnawave/nodes.json
STATE_FILE=/etc/remnawave/state.json
LOG_DIR=/var/log/remnawave
GEOIP_PATH=/etc/sing-box/geoip.db
GEOSITE_PATH=/etc/sing-box/geosite.db
```

**Step 3: Commit**

```bash
git add src/ tests/ systemd/ config.env.example
git commit -m "chore: project scaffold"
```

---

### Task 2: URI Parser

**Files:**
- Create: `src/uri_parser.py`
- Create: `tests/test_uri_parser.py`

**Step 1: Write failing tests**

Create `tests/test_uri_parser.py`:

```python
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
```

**Step 2: Run tests to verify they fail**

```bash
python -m pytest tests/test_uri_parser.py -v 2>&1 | head -30
```

Expected: `ImportError: cannot import name 'parse_uri'`

**Step 3: Implement `src/uri_parser.py`**

```python
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


def _split_host_port(hostport: str) -> tuple[str, str]:
    """Handle IPv6 addresses like [::1]:443."""
    if hostport.startswith("["):
        bracket_end = hostport.index("]")
        host = hostport[1:bracket_end]
        port = hostport[bracket_end + 2:]
    else:
        host, port = hostport.rsplit(":", 1)
    return host, port
```

**Step 4: Run tests to verify they pass**

```bash
python -m pytest tests/test_uri_parser.py -v
```

Expected: All tests PASS.

**Step 5: Commit**

```bash
git add src/uri_parser.py tests/test_uri_parser.py
git commit -m "feat: URI parser for vless/vmess/trojan"
```

---

### Task 3: Subscription Fetcher

**Files:**
- Create: `src/subscription.py`
- Create: `tests/test_subscription.py`

**Step 1: Write failing tests**

Create `tests/test_subscription.py`:

```python
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
```

**Step 2: Run tests to verify they fail**

```bash
python -m pytest tests/test_subscription.py -v 2>&1 | head -20
```

Expected: `ImportError: cannot import name 'fetch_subscription'`

**Step 3: Implement `src/subscription.py`**

```python
"""
Fetch and decode Remnawave subscription.

Remnawave GET /sub/{token} returns either:
  - Plain text with one URI per line
  - Base64-encoded version of the same
"""
from __future__ import annotations
import base64
import urllib.error
import urllib.request
from typing import List

from .uri_parser import ParsedNode, parse_uri

TIMEOUT_SECONDS = 15
USER_AGENT = "remnawave-sync/1.0"


def fetch_subscription(url: str) -> List[ParsedNode]:
    """Fetch subscription URL and return list of parsed nodes. Raises ConnectionError on failure."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as resp:
            if resp.status != 200:
                raise ConnectionError(f"Subscription returned HTTP {resp.status}")
            raw = resp.read().decode("utf-8", errors="replace")
    except urllib.error.URLError as exc:
        raise ConnectionError(f"Failed to fetch subscription: {exc}") from exc
    return decode_subscription(raw)


def decode_subscription(raw: str) -> List[ParsedNode]:
    """Parse raw subscription text (plain or base64) into nodes."""
    if not raw.strip():
        return []

    text = _maybe_decode_base64(raw.strip())
    nodes: List[ParsedNode] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        node = parse_uri(line)
        if node is not None:
            nodes.append(node)
    return nodes


def _maybe_decode_base64(text: str) -> str:
    """Return decoded text if it looks like base64, otherwise original."""
    # URI lines start with known schemes — if no scheme found, assume base64
    first_line = text.splitlines()[0] if text else ""
    known_schemes = ("vless://", "vmess://", "trojan://", "ss://", "ssr://")
    if any(first_line.startswith(s) for s in known_schemes):
        return text
    try:
        padding = 4 - len(text) % 4
        padded = text + ("=" * padding if padding != 4 else "")
        decoded = base64.b64decode(padded).decode("utf-8")
        # Validate it looks like URI lines
        if any(decoded.startswith(s) for s in known_schemes):
            return decoded
        # Try per-line check
        first = decoded.splitlines()[0] if decoded.splitlines() else ""
        if any(first.startswith(s) for s in known_schemes):
            return decoded
    except Exception:
        pass
    return text
```

**Step 4: Run tests**

```bash
python -m pytest tests/test_subscription.py -v
```

Expected: All tests PASS.

**Step 5: Commit**

```bash
git add src/subscription.py tests/test_subscription.py
git commit -m "feat: subscription fetcher with base64 auto-detection"
```

---

### Task 4: sing-box Config Generator

**Files:**
- Create: `src/config_generator.py`
- Create: `tests/test_config_generator.py`

**Step 1: Write failing tests**

Create `tests/test_config_generator.py`:

```python
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
```

**Step 2: Run tests to verify they fail**

```bash
python -m pytest tests/test_config_generator.py -v 2>&1 | head -20
```

Expected: `ImportError`

**Step 3: Implement `src/config_generator.py`**

```python
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
            {"tag": "local", "address": "223.5.5.5", "detour": "direct"},
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
```

**Step 4: Run tests**

```bash
python -m pytest tests/test_config_generator.py -v
```

Expected: All tests PASS.

**Step 5: Commit**

```bash
git add src/config_generator.py tests/test_config_generator.py
git commit -m "feat: sing-box config generator"
```

---

### Task 5: State Manager

**Files:**
- Create: `src/state_manager.py`
- Create: `tests/test_state_manager.py`

**Step 1: Write failing tests**

Create `tests/test_state_manager.py`:

```python
import json
import pytest
import tempfile
from pathlib import Path
from src.state_manager import StateManager
from src.uri_parser import ParsedNode


def make_node(name: str) -> ParsedNode:
    return ParsedNode(
        protocol="vless", host=f"{name}.example.com", port=443,
        name=name, uuid="uuid", security="reality",
        reality_pbk="KEY", reality_sid="sid",
    )


class TestStateManager:
    def setup_method(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.nodes_file = self.tmp / "nodes.json"
        self.state_file = self.tmp / "state.json"
        self.sm = StateManager(str(self.nodes_file), str(self.state_file))

    def test_save_and_load_nodes(self):
        nodes = [make_node("NL-1"), make_node("DE-1")]
        self.sm.save_nodes(nodes)
        loaded = self.sm.load_nodes()
        assert len(loaded) == 2
        assert loaded[0].host == "NL-1.example.com"
        assert loaded[1].host == "DE-1.example.com"

    def test_load_nodes_missing_file_returns_empty(self):
        assert self.sm.load_nodes() == []

    def test_current_node_index_default_zero(self):
        assert self.sm.get_current_index() == 0

    def test_set_current_index(self):
        self.sm.set_current_index(2)
        assert self.sm.get_current_index() == 2
        # Persists across new instance
        sm2 = StateManager(str(self.nodes_file), str(self.state_file))
        assert sm2.get_current_index() == 2

    def test_increment_index_wraps(self):
        nodes = [make_node("A"), make_node("B"), make_node("C")]
        self.sm.save_nodes(nodes)
        self.sm.set_current_index(2)
        new_idx = self.sm.rotate_node()
        assert new_idx == 0  # wraps to beginning

    def test_increment_index_normal(self):
        nodes = [make_node("A"), make_node("B"), make_node("C")]
        self.sm.save_nodes(nodes)
        self.sm.set_current_index(0)
        new_idx = self.sm.rotate_node()
        assert new_idx == 1

    def test_get_current_node(self):
        nodes = [make_node("A"), make_node("B")]
        self.sm.save_nodes(nodes)
        self.sm.set_current_index(1)
        node = self.sm.get_current_node()
        assert node.name == "B"

    def test_get_current_node_empty_returns_none(self):
        assert self.sm.get_current_node() is None

    def test_fail_count(self):
        self.sm.increment_fail_count()
        self.sm.increment_fail_count()
        assert self.sm.get_fail_count() == 2
        self.sm.reset_fail_count()
        assert self.sm.get_fail_count() == 0
```

**Step 2: Run tests to verify they fail**

```bash
python -m pytest tests/test_state_manager.py -v 2>&1 | head -10
```

**Step 3: Implement `src/state_manager.py`**

```python
"""
Persist nodes list and current node index to JSON files.
"""
from __future__ import annotations
import json
from dataclasses import asdict
from pathlib import Path
from typing import List, Optional

from .uri_parser import ParsedNode


class StateManager:
    def __init__(self, nodes_file: str, state_file: str):
        self._nodes_file = Path(nodes_file)
        self._state_file = Path(state_file)

    # ── Nodes ─────────────────────────────────────────────────────────────────

    def save_nodes(self, nodes: List[ParsedNode]) -> None:
        self._nodes_file.parent.mkdir(parents=True, exist_ok=True)
        data = [n.to_dict() for n in nodes]
        self._nodes_file.write_text(json.dumps(data, indent=2))

    def load_nodes(self) -> List[ParsedNode]:
        if not self._nodes_file.exists():
            return []
        try:
            data = json.loads(self._nodes_file.read_text())
            return [ParsedNode(**d) for d in data]
        except Exception:
            return []

    # ── State ─────────────────────────────────────────────────────────────────

    def _load_state(self) -> dict:
        if not self._state_file.exists():
            return {"current_node": 0, "fail_count": 0}
        try:
            return json.loads(self._state_file.read_text())
        except Exception:
            return {"current_node": 0, "fail_count": 0}

    def _save_state(self, state: dict) -> None:
        self._state_file.parent.mkdir(parents=True, exist_ok=True)
        self._state_file.write_text(json.dumps(state, indent=2))

    def get_current_index(self) -> int:
        return self._load_state().get("current_node", 0)

    def set_current_index(self, index: int) -> None:
        state = self._load_state()
        state["current_node"] = index
        self._save_state(state)

    def rotate_node(self) -> int:
        nodes = self.load_nodes()
        if not nodes:
            return 0
        new_idx = (self.get_current_index() + 1) % len(nodes)
        self.set_current_index(new_idx)
        return new_idx

    def get_current_node(self) -> Optional[ParsedNode]:
        nodes = self.load_nodes()
        if not nodes:
            return None
        idx = self.get_current_index() % len(nodes)
        return nodes[idx]

    def get_fail_count(self) -> int:
        return self._load_state().get("fail_count", 0)

    def increment_fail_count(self) -> int:
        state = self._load_state()
        state["fail_count"] = state.get("fail_count", 0) + 1
        self._save_state(state)
        return state["fail_count"]

    def reset_fail_count(self) -> None:
        state = self._load_state()
        state["fail_count"] = 0
        self._save_state(state)
```

**Step 4: Run tests**

```bash
python -m pytest tests/test_state_manager.py -v
```

**Step 5: Commit**

```bash
git add src/state_manager.py tests/test_state_manager.py
git commit -m "feat: state manager for nodes and current index"
```

---

### Task 6: Binary Manager (sing-box + geo files)

**Files:**
- Create: `src/binary_manager.py`

> No unit tests for this module — it makes network calls and writes binaries.
> It will be verified during integration/install testing on VyOS.

**Step 1: Implement `src/binary_manager.py`**

```python
"""
Download and verify sing-box binary and geo data files.

sing-box releases: https://github.com/SagerNet/sing-box/releases
geoip.db:          https://github.com/SagerNet/sing-geoip/releases
geosite.db:        https://github.com/SagerNet/sing-geosite/releases
"""
from __future__ import annotations
import hashlib
import json
import logging
import os
import platform
import stat
import tarfile
import tempfile
import urllib.request
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)

GITHUB_API = "https://api.github.com"
SING_BOX_REPO = "SagerNet/sing-box"
GEOIP_REPO = "SagerNet/sing-geoip"
GEOSITE_REPO = "SagerNet/sing-geosite"


def ensure_sing_box(install_path: str) -> str:
    """Ensure sing-box binary exists at install_path. Download if missing."""
    p = Path(install_path)
    if p.exists() and os.access(str(p), os.X_OK):
        log.info("sing-box already present: %s", install_path)
        return install_path

    log.info("Downloading sing-box...")
    url = _get_sing_box_download_url()
    _download_sing_box(url, install_path)
    log.info("sing-box installed to %s", install_path)
    return install_path


def ensure_geo_files(geoip_path: str, geosite_path: str) -> None:
    """Ensure geoip.db and geosite.db exist. Download if missing."""
    if not Path(geoip_path).exists():
        log.info("Downloading geoip.db...")
        url = _get_latest_asset_url(GEOIP_REPO, "geoip.db")
        _download_file(url, geoip_path)
        log.info("geoip.db saved to %s", geoip_path)

    if not Path(geosite_path).exists():
        log.info("Downloading geosite.db...")
        url = _get_latest_asset_url(GEOSITE_REPO, "geosite.db")
        _download_file(url, geosite_path)
        log.info("geosite.db saved to %s", geosite_path)


# ── Internal helpers ──────────────────────────────────────────────────────────

def _get_arch() -> str:
    machine = platform.machine().lower()
    mapping = {
        "x86_64": "amd64", "amd64": "amd64",
        "aarch64": "arm64", "arm64": "arm64",
        "armv7l": "armv7",
    }
    return mapping.get(machine, "amd64")


def _get_sing_box_download_url() -> str:
    release = _fetch_latest_release(SING_BOX_REPO)
    version = release["tag_name"].lstrip("v")
    arch = _get_arch()
    # e.g. sing-box-1.9.0-linux-amd64.tar.gz
    asset_name = f"sing-box-{version}-linux-{arch}.tar.gz"
    for asset in release["assets"]:
        if asset["name"] == asset_name:
            return asset["browser_download_url"]
    raise RuntimeError(f"Could not find asset {asset_name} in sing-box release")


def _get_latest_asset_url(repo: str, filename: str) -> str:
    release = _fetch_latest_release(repo)
    for asset in release["assets"]:
        if asset["name"] == filename:
            return asset["browser_download_url"]
    raise RuntimeError(f"Could not find {filename} in {repo} release")


def _fetch_latest_release(repo: str) -> dict:
    url = f"{GITHUB_API}/repos/{repo}/releases/latest"
    req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())


def _download_file(url: str, dest: str) -> None:
    Path(dest).parent.mkdir(parents=True, exist_ok=True)
    req = urllib.request.Request(url, headers={"User-Agent": "remnawave-sync/1.0"})
    with urllib.request.urlopen(req, timeout=120) as resp:
        Path(dest).write_bytes(resp.read())


def _download_sing_box(url: str, dest: str) -> None:
    Path(dest).parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        tar_path = os.path.join(tmp, "sing-box.tar.gz")
        _download_file(url, tar_path)
        with tarfile.open(tar_path, "r:gz") as tar:
            # Find the sing-box binary inside the archive
            for member in tar.getmembers():
                if member.name.endswith("/sing-box") or member.name == "sing-box":
                    member.name = "sing-box"
                    tar.extract(member, tmp)
                    break
            else:
                raise RuntimeError("sing-box binary not found in archive")
        extracted = os.path.join(tmp, "sing-box")
        import shutil
        shutil.copy2(extracted, dest)
    # Make executable
    current = os.stat(dest).st_mode
    os.chmod(dest, current | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
```

**Step 2: Commit**

```bash
git add src/binary_manager.py
git commit -m "feat: binary manager for sing-box and geo files"
```

---

### Task 7: Main Sync Script

**Files:**
- Create: `src/sync.py`

**Step 1: Implement `src/sync.py`**

```python
#!/usr/bin/env python3
"""
remnawave-sync — fetch subscription and update sing-box config.

Usage:
  python3 sync.py [--config /etc/remnawave/config.env]
"""
from __future__ import annotations
import argparse
import hashlib
import json
import logging
import os
import subprocess
import sys
from pathlib import Path

# Allow running directly as script
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.binary_manager import ensure_sing_box, ensure_geo_files
from src.config_generator import ConfigSettings, generate_config
from src.state_manager import StateManager
from src.subscription import fetch_subscription

log = logging.getLogger("remnawave-sync")


def load_env(path: str) -> dict:
    env = {}
    try:
        for line in Path(path).read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            env[key.strip()] = value.strip()
    except FileNotFoundError:
        pass
    return env


def main(config_path: str = "/etc/remnawave/config.env") -> int:
    env = load_env(config_path)
    env = {**os.environ, **env}  # env file takes precedence

    log_dir = env.get("LOG_DIR", "/var/log/remnawave")
    Path(log_dir).mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[
            logging.FileHandler(f"{log_dir}/sync.log"),
            logging.StreamHandler(),
        ],
    )

    subscription_url = env.get("SUBSCRIPTION_URL", "")
    if not subscription_url:
        log.error("SUBSCRIPTION_URL not set in %s", config_path)
        return 1

    sing_box_bin  = env.get("XRAY_BIN", "/usr/local/bin/sing-box")
    xray_config   = env.get("XRAY_CONFIG", "/etc/sing-box/config.json")
    nodes_file    = env.get("NODES_FILE", "/etc/remnawave/nodes.json")
    state_file    = env.get("STATE_FILE", "/etc/remnawave/state.json")
    geoip_path    = env.get("GEOIP_PATH", "/etc/sing-box/geoip.db")
    geosite_path  = env.get("GEOSITE_PATH", "/etc/sing-box/geosite.db")

    settings = ConfigSettings(
        tun_interface=env.get("TUN_INTERFACE", "tun0"),
        tun_address=env.get("TUN_ADDRESS", "172.19.0.1/30"),
        geo_direct_ip=env.get("GEO_DIRECT_IP", "private,ru").split(","),
        geo_direct_site=env.get("GEO_DIRECT_SITE", "ru").split(","),
        geoip_path=geoip_path,
        geosite_path=geosite_path,
    )

    sm = StateManager(nodes_file, state_file)

    # 1. Ensure binaries/geo files are present
    try:
        ensure_sing_box(sing_box_bin)
        ensure_geo_files(geoip_path, geosite_path)
    except Exception as exc:
        log.error("Binary setup failed: %s", exc)
        return 1

    # 2. Fetch subscription
    try:
        nodes = fetch_subscription(subscription_url)
        log.info("Fetched %d nodes from subscription", len(nodes))
    except ConnectionError as exc:
        log.warning("Subscription fetch failed: %s — using cached nodes", exc)
        nodes = sm.load_nodes()
        if not nodes:
            log.error("No cached nodes available")
            return 1

    if not nodes:
        log.error("Subscription returned 0 nodes")
        return 1

    # 3. Update nodes cache (reset index if node count changed)
    old_nodes = sm.load_nodes()
    sm.save_nodes(nodes)
    if len(nodes) != len(old_nodes):
        sm.set_current_index(0)
        log.info("Node list changed (%d → %d), reset to node 0", len(old_nodes), len(nodes))

    # 4. Generate config for current node
    current_node = sm.get_current_node()
    if current_node is None:
        log.error("No current node")
        return 1

    log.info("Generating config for node: %s (%s:%d)", current_node.name, current_node.host, current_node.port)
    config = generate_config(current_node, settings)
    config_json = json.dumps(config, indent=2)

    # 5. Compare with existing config — only restart if changed
    config_path_obj = Path(xray_config)
    config_path_obj.parent.mkdir(parents=True, exist_ok=True)

    old_hash = _hash_file(xray_config)
    new_hash = hashlib.sha256(config_json.encode()).hexdigest()

    if old_hash == new_hash:
        log.info("Config unchanged, no restart needed")
        return 0

    config_path_obj.write_text(config_json)
    log.info("Config written to %s", xray_config)

    # 6. Reload/start sing-box
    _reload_sing_box()
    return 0


def _hash_file(path: str) -> str:
    try:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    except FileNotFoundError:
        return ""


def _reload_sing_box() -> None:
    result = subprocess.run(
        ["systemctl", "reload-or-restart", "sing-box"],
        capture_output=True, text=True,
    )
    if result.returncode == 0:
        log.info("sing-box reloaded")
    else:
        log.error("sing-box reload failed: %s", result.stderr)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="/etc/remnawave/config.env")
    args = parser.parse_args()
    sys.exit(main(args.config))
```

**Step 2: Commit**

```bash
git add src/sync.py
git commit -m "feat: main sync orchestrator"
```

---

### Task 8: Heartbeat Script

**Files:**
- Create: `src/heartbeat.py`
- Create: `tests/test_heartbeat.py`

**Step 1: Write failing tests**

Create `tests/test_heartbeat.py`:

```python
import pytest
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock
from src.uri_parser import ParsedNode
from src.state_manager import StateManager


def make_node(name: str) -> ParsedNode:
    return ParsedNode(
        protocol="vless", host=f"{name}.com", port=443,
        name=name, uuid="uuid", security="reality",
        reality_pbk="KEY", reality_sid="sid",
    )


def make_sm_with_nodes(tmp_path, nodes, index=0):
    sm = StateManager(
        str(tmp_path / "nodes.json"),
        str(tmp_path / "state.json"),
    )
    sm.save_nodes(nodes)
    sm.set_current_index(index)
    return sm


class TestCheckConnectivity:
    def test_success_returns_true(self):
        from src.heartbeat import check_connectivity
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        with patch("urllib.request.urlopen", return_value=mock_resp):
            assert check_connectivity("cp.cloudflare.com", timeout=5) is True

    def test_timeout_returns_false(self):
        import urllib.error
        from src.heartbeat import check_connectivity
        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("timeout")):
            assert check_connectivity("cp.cloudflare.com", timeout=1) is False

    def test_non_200_returns_false(self):
        from src.heartbeat import check_connectivity
        mock_resp = MagicMock()
        mock_resp.status = 503
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        with patch("urllib.request.urlopen", return_value=mock_resp):
            assert check_connectivity("cp.cloudflare.com", timeout=5) is False


class TestHeartbeatLogic:
    def setup_method(self):
        self.tmp = Path(tempfile.mkdtemp())

    def test_success_resets_fail_count(self):
        from src.heartbeat import run_heartbeat_check
        sm = make_sm_with_nodes(self.tmp, [make_node("A"), make_node("B")])
        sm.increment_fail_count()
        sm.increment_fail_count()

        with patch("src.heartbeat.check_connectivity", return_value=True):
            with patch("src.heartbeat._reload_sing_box"):
                switched = run_heartbeat_check(sm, fail_threshold=2, heartbeat_host="h.com", timeout=5)

        assert switched is False
        assert sm.get_fail_count() == 0

    def test_single_failure_no_switch(self):
        from src.heartbeat import run_heartbeat_check
        sm = make_sm_with_nodes(self.tmp, [make_node("A"), make_node("B")])

        with patch("src.heartbeat.check_connectivity", return_value=False):
            with patch("src.heartbeat._reload_sing_box"):
                switched = run_heartbeat_check(sm, fail_threshold=2, heartbeat_host="h.com", timeout=5)

        assert switched is False
        assert sm.get_fail_count() == 1
        assert sm.get_current_index() == 0

    def test_threshold_reached_switches_node(self):
        from src.heartbeat import run_heartbeat_check
        sm = make_sm_with_nodes(self.tmp, [make_node("A"), make_node("B"), make_node("C")])
        sm.increment_fail_count()  # already at 1

        with patch("src.heartbeat.check_connectivity", return_value=False):
            with patch("src.heartbeat._reload_sing_box") as mock_reload:
                switched = run_heartbeat_check(sm, fail_threshold=2, heartbeat_host="h.com", timeout=5)

        assert switched is True
        assert sm.get_current_index() == 1
        assert sm.get_fail_count() == 0
        mock_reload.assert_called_once()

    def test_rotation_wraps_around(self):
        from src.heartbeat import run_heartbeat_check
        sm = make_sm_with_nodes(self.tmp, [make_node("A"), make_node("B")], index=1)
        sm.increment_fail_count()  # at 1

        with patch("src.heartbeat.check_connectivity", return_value=False):
            with patch("src.heartbeat._reload_sing_box"):
                run_heartbeat_check(sm, fail_threshold=2, heartbeat_host="h.com", timeout=5)

        assert sm.get_current_index() == 0  # wrapped
```

**Step 2: Run tests to verify they fail**

```bash
python -m pytest tests/test_heartbeat.py -v 2>&1 | head -15
```

**Step 3: Implement `src/heartbeat.py`**

```python
#!/usr/bin/env python3
"""
remnawave-heartbeat — check connectivity and rotate nodes on failure.

Usage:
  python3 heartbeat.py [--config /etc/remnawave/config.env]
"""
from __future__ import annotations
import argparse
import json
import logging
import os
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.config_generator import ConfigSettings, generate_config
from src.state_manager import StateManager

log = logging.getLogger("remnawave-heartbeat")


def check_connectivity(host: str, timeout: int = 5) -> bool:
    """Return True if we can reach the heartbeat host via HTTP."""
    url = f"https://{host}"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return resp.status == 200
    except Exception:
        return False


def run_heartbeat_check(
    sm: StateManager,
    fail_threshold: int,
    heartbeat_host: str,
    timeout: int,
) -> bool:
    """Run one heartbeat check. Returns True if node was switched."""
    if check_connectivity(heartbeat_host, timeout):
        if sm.get_fail_count() > 0:
            log.info("Connectivity restored, resetting fail count")
        sm.reset_fail_count()
        return False

    count = sm.increment_fail_count()
    log.warning("Connectivity check failed (%d/%d)", count, fail_threshold)

    if count >= fail_threshold:
        old_idx = sm.get_current_index()
        new_idx = sm.rotate_node()
        sm.reset_fail_count()
        node = sm.get_current_node()
        node_name = node.name if node else "unknown"
        log.warning("Switching node %d → %d (%s)", old_idx, new_idx, node_name)
        _apply_new_node(sm)
        return True

    return False


def _apply_new_node(sm: StateManager) -> None:
    """Regenerate config for new current node and reload sing-box."""
    from src.sync import load_env
    env = load_env("/etc/remnawave/config.env")
    env = {**os.environ, **env}

    node = sm.get_current_node()
    if node is None:
        log.error("No node available after rotation")
        return

    settings = ConfigSettings(
        tun_interface=env.get("TUN_INTERFACE", "tun0"),
        tun_address=env.get("TUN_ADDRESS", "172.19.0.1/30"),
        geo_direct_ip=env.get("GEO_DIRECT_IP", "private,ru").split(","),
        geo_direct_site=env.get("GEO_DIRECT_SITE", "ru").split(","),
        geoip_path=env.get("GEOIP_PATH", "/etc/sing-box/geoip.db"),
        geosite_path=env.get("GEOSITE_PATH", "/etc/sing-box/geosite.db"),
    )

    config = generate_config(node, settings)
    xray_config = env.get("XRAY_CONFIG", "/etc/sing-box/config.json")
    Path(xray_config).write_text(json.dumps(config, indent=2))
    log.info("Config updated for node: %s", node.name)
    _reload_sing_box()


def _reload_sing_box() -> None:
    result = subprocess.run(
        ["systemctl", "reload-or-restart", "sing-box"],
        capture_output=True, text=True,
    )
    if result.returncode == 0:
        log.info("sing-box reloaded")
    else:
        log.error("sing-box reload failed: %s", result.stderr)


def main(config_path: str = "/etc/remnawave/config.env") -> int:
    from src.sync import load_env
    env = load_env(config_path)
    env = {**os.environ, **env}

    log_dir = env.get("LOG_DIR", "/var/log/remnawave")
    Path(log_dir).mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[
            logging.FileHandler(f"{log_dir}/heartbeat.log"),
            logging.StreamHandler(),
        ],
    )

    sm = StateManager(
        env.get("NODES_FILE", "/etc/remnawave/nodes.json"),
        env.get("STATE_FILE", "/etc/remnawave/state.json"),
    )

    run_heartbeat_check(
        sm,
        fail_threshold=int(env.get("HEARTBEAT_FAIL_THRESHOLD", "2")),
        heartbeat_host=env.get("HEARTBEAT_HOST", "cp.cloudflare.com"),
        timeout=int(env.get("HEARTBEAT_TIMEOUT", "5")),
    )
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="/etc/remnawave/config.env")
    args = parser.parse_args()
    sys.exit(main(args.config))
```

**Step 4: Run all tests**

```bash
python -m pytest tests/ -v
```

Expected: All tests PASS.

**Step 5: Commit**

```bash
git add src/heartbeat.py tests/test_heartbeat.py
git commit -m "feat: heartbeat with automatic node rotation"
```

---

### Task 9: Systemd Units

**Files:**
- Create: `systemd/sing-box.service`
- Create: `systemd/remnawave-sync.service`
- Create: `systemd/remnawave-sync.timer`
- Create: `systemd/remnawave-heartbeat.service`
- Create: `systemd/remnawave-heartbeat.timer`

**Step 1: Create `systemd/sing-box.service`**

```ini
[Unit]
Description=sing-box proxy service
After=network-online.target
Wants=network-online.target
Documentation=https://sing-box.sagernet.org

[Service]
Type=simple
User=root
ExecStartPre=/usr/local/bin/sing-box check -c /etc/sing-box/config.json
ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5s
LimitNOFILE=65536
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_SYS_PTRACE
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_SYS_PTRACE

[Install]
WantedBy=multi-user.target
```

**Step 2: Create `systemd/remnawave-sync.service`**

```ini
[Unit]
Description=Remnawave config sync (oneshot)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /usr/local/lib/remnawave/sync.py --config /etc/remnawave/config.env
StandardOutput=journal
StandardError=journal
```

**Step 3: Create `systemd/remnawave-sync.timer`**

```ini
[Unit]
Description=Remnawave config sync timer
Requires=remnawave-sync.service

[Timer]
OnBootSec=15s
OnUnitActiveSec=10min
Unit=remnawave-sync.service

[Install]
WantedBy=timers.target
```

**Step 4: Create `systemd/remnawave-heartbeat.service`**

```ini
[Unit]
Description=Remnawave heartbeat check (oneshot)
After=sing-box.service

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /usr/local/lib/remnawave/heartbeat.py --config /etc/remnawave/config.env
StandardOutput=journal
StandardError=journal
```

**Step 5: Create `systemd/remnawave-heartbeat.timer`**

```ini
[Unit]
Description=Remnawave heartbeat timer
Requires=remnawave-heartbeat.service

[Timer]
OnBootSec=30s
OnUnitActiveSec=30s
Unit=remnawave-heartbeat.service

[Install]
WantedBy=timers.target
```

**Step 6: Commit**

```bash
git add systemd/
git commit -m "feat: systemd service and timer units"
```

---

### Task 10: Install Script

**Files:**
- Create: `install.sh`

**Step 1: Create `install.sh`**

```bash
#!/bin/bash
# Install remnawave-sync on VyOS
set -euo pipefail

INSTALL_LIB="/usr/local/lib/remnawave"
CONFIG_DIR="/etc/remnawave"
SING_BOX_DIR="/etc/sing-box"

echo "=== Remnawave Sync Installer ==="

# 1. Create directories
mkdir -p "$INSTALL_LIB" "$CONFIG_DIR" "$SING_BOX_DIR" /var/log/remnawave

# 2. Copy Python source
cp -r src/ "$INSTALL_LIB/"
cp src/sync.py "$INSTALL_LIB/sync.py"
cp src/heartbeat.py "$INSTALL_LIB/heartbeat.py"
touch "$INSTALL_LIB/__init__.py"
touch "$INSTALL_LIB/src/__init__.py"

# 3. Install config if not present
if [ ! -f "$CONFIG_DIR/config.env" ]; then
    cp config.env.example "$CONFIG_DIR/config.env"
    echo ""
    echo ">>> IMPORTANT: Edit $CONFIG_DIR/config.env and set SUBSCRIPTION_URL <<<"
    echo ""
fi

# 4. Install systemd units
cp systemd/sing-box.service /etc/systemd/system/
cp systemd/remnawave-sync.service /etc/systemd/system/
cp systemd/remnawave-sync.timer /etc/systemd/system/
cp systemd/remnawave-heartbeat.service /etc/systemd/system/
cp systemd/remnawave-heartbeat.timer /etc/systemd/system/

systemctl daemon-reload

# 5. Run first sync (downloads sing-box + geo files)
echo "Running initial sync (this may take a minute — downloading sing-box)..."
python3 "$INSTALL_LIB/sync.py" --config "$CONFIG_DIR/config.env"

# 6. Set up TUN interface
TUN_IF=$(grep TUN_INTERFACE "$CONFIG_DIR/config.env" | cut -d= -f2 | tr -d ' ' || echo "tun0")
TUN_ADDR=$(grep TUN_ADDRESS "$CONFIG_DIR/config.env" | cut -d= -f2 | tr -d ' ' || echo "172.19.0.1/30")

if ! ip link show "$TUN_IF" &>/dev/null; then
    ip tuntap add mode tun "$TUN_IF" || true
    ip addr add "$TUN_ADDR" dev "$TUN_IF" || true
    ip link set "$TUN_IF" up || true
fi

# 7. Enable and start services
systemctl enable --now sing-box.service
systemctl enable --now remnawave-sync.timer
systemctl enable --now remnawave-heartbeat.timer

echo ""
echo "=== Installation complete ==="
echo "Status:"
systemctl is-active sing-box.service remnawave-sync.timer remnawave-heartbeat.timer
echo ""
echo "Logs:"
echo "  journalctl -u sing-box -f"
echo "  tail -f /var/log/remnawave/sync.log"
echo "  tail -f /var/log/remnawave/heartbeat.log"
echo ""
echo "Manual sync:      python3 $INSTALL_LIB/sync.py"
echo "Manual heartbeat: python3 $INSTALL_LIB/heartbeat.py"
```

**Step 2: Make executable and commit**

```bash
chmod +x install.sh
git add install.sh
git commit -m "feat: install script for VyOS"
```

---

### Task 11: Run Full Test Suite

**Step 1: Run all tests**

```bash
python -m pytest tests/ -v --tb=short
```

Expected output: All tests PASS, 0 failures.

**Step 2: Commit if any fixes were needed**

```bash
git add -A
git commit -m "test: full suite passing"
```

---

## Quick Reference

```
# After editing code on dev machine:
python -m pytest tests/ -v

# On VyOS (first install):
bash install.sh

# Check status:
systemctl status sing-box remnawave-sync.timer remnawave-heartbeat.timer

# Force sync now:
systemctl start remnawave-sync.service

# Watch logs:
journalctl -u sing-box -f
tail -f /var/log/remnawave/sync.log
tail -f /var/log/remnawave/heartbeat.log

# Change subscription URL:
nano /etc/remnawave/config.env
systemctl start remnawave-sync.service
```
