"""Clients HTTP partagés (scans, connecteurs)."""
from __future__ import annotations

import os
import random

import requests

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
]
_proxy_env = os.environ.get('PROXY_LIST', '')
PROXIES = [p.strip() for p in _proxy_env.split(',') if p.strip()]


def make_http_session():
    s = requests.Session()
    s.headers.update({'User-Agent': random.choice(USER_AGENTS)})
    if PROXIES:
        proxy = random.choice(PROXIES)
        s.proxies = {'http': proxy, 'https': proxy}
    return s


def safe_get(url, timeout=15, **kwargs):
    try:
        s = make_http_session()
        from services.http_client import SSL_VERIFY
        return s.get(url, timeout=timeout, verify=SSL_VERIFY, **kwargs)
    except Exception:
        return None
