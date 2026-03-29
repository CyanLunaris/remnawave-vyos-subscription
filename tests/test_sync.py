from src.sync import build_config_settings


def test_build_config_settings_reads_performance_env():
    settings = build_config_settings({
        "DNS_SERVER": "https://dns.google/dns-query",
        "ROUTE_SNIFF_TIMEOUT": "80ms",
        "TUN_MTU": "1320",
        "TUN_GSO": "true",
        "MULTIPLEX_MAX_CONNECTIONS": "8",
    })
    assert settings.dns_server == "https://dns.google/dns-query"
    assert settings.route_sniff_timeout == "80ms"
    assert settings.tun_mtu == 1320
    assert settings.tun_gso is True
    assert settings.multiplex_max_connections == 8


def test_build_config_settings_falls_back_on_invalid_ints():
    settings = build_config_settings({
        "TUN_MTU": "invalid",
        "MULTIPLEX_MAX_CONNECTIONS": "nope",
    })
    assert settings.tun_mtu == 1400
    assert settings.multiplex_max_connections == 4
