"""Tests sanitization URL / pseudos."""
from services.url_sanitize import (
    normalize_http_url,
    sanitize_domain_host,
    sanitize_username,
    safe_path_segment,
)


def test_sanitize_username_strips_spaces():
    assert sanitize_username('wesley schinkel') == 'wesleyschinkel'


def test_sanitize_domain_rejects_phone():
    assert sanitize_domain_host('+48 574 136 164') is None
    assert sanitize_domain_host('Numer +48 574') is None


def test_normalize_http_url_rejects_spaces():
    assert normalize_http_url('https://wesley schinkel.tumblr.com') is None


def test_normalize_http_url_accepts_instagram():
    u = normalize_http_url('https://www.instagram.com/api/v1/users/web_profile_info/?username=test')
    assert u and 'instagram.com' in u


def test_safe_path_segment():
    assert safe_path_segment('  foo bar  ') == 'foobar'
