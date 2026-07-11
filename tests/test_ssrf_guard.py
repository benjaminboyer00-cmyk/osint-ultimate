"""Garde anti-SSRF : les scans ne doivent pas viser des ressources internes."""
from services.ssrf_guard import ip_is_internal, host_is_public
from services.url_sanitize import normalize_http_url


def test_internal_ips_blocked():
    for ip in ['127.0.0.1', '10.0.0.5', '192.168.1.1', '169.254.169.254',
               '172.16.0.1', '::1', '0.0.0.0']:
        assert ip_is_internal(ip), ip
        assert host_is_public(ip) is False, ip


def test_public_ips_allowed():
    for ip in ['8.8.8.8', '1.1.1.1']:
        assert not ip_is_internal(ip)
        assert host_is_public(ip) is True


def test_localhost_domain_blocked():
    assert host_is_public('localhost') is False


def test_normalize_url_blocks_internal():
    assert normalize_http_url('http://127.0.0.1/') is None
    assert normalize_http_url('http://10.0.0.5/admin') is None
    assert normalize_http_url('http://169.254.169.254/latest/meta-data/') is None
    assert normalize_http_url('https://example.com/') == 'https://example.com/'


def test_scan_ip_refuses_internal(app):
    from scans.core_scans import scan_ip
    with app.app_context():
        out = scan_ip('192.168.1.1')
        assert 'Erreur' in out and 'SSRF' in out['Erreur']


def test_allow_private_escape_hatch(monkeypatch):
    monkeypatch.setenv('ALLOW_PRIVATE_SCAN_TARGETS', '1')
    assert ip_is_internal('10.0.0.5') is False
    assert host_is_public('127.0.0.1') is True
