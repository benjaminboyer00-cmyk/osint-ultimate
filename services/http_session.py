"""
Gestionnaire de sessions HTTP — rotation User-Agent, proxies, blacklist temporaire.
"""
import logging
import os
import random
import threading
import time

import requests

from services.http_client import SSL_VERIFY, USER_AGENTS

logger = logging.getLogger(__name__)

_dead_proxies: dict[str, float] = {}
_dead_lock = threading.Lock()
PROXY_BLACKLIST_SEC = 600


def _proxy_list(options: dict | None) -> list[str]:
    opts = options or {}
    raw = opts.get('_proxy_list') or os.environ.get('PROXY_LIST', '')
    return [p.strip() for p in str(raw).split(',') if p.strip()]


def _pick_proxy(options: dict | None) -> str | None:
    now = time.time()
    candidates = []
    with _dead_lock:
        for p in _proxy_list(options):
            until = _dead_proxies.get(p, 0)
            if until <= now:
                candidates.append(p)
    if not candidates:
        return None
    return random.choice(candidates)


def mark_proxy_dead(proxy: str) -> None:
    if not proxy:
        return
    with _dead_lock:
        _dead_proxies[proxy] = time.time() + PROXY_BLACKLIST_SEC


def pick_user_agent(options: dict | None = None) -> str:
    opts = options or {}
    if opts.get('_stealth_mode'):
        try:
            from fake_useragent import UserAgent
            return UserAgent().random
        except Exception:
            pass
    return random.choice(USER_AGENTS)


class SessionManager:
    """Session requests réutilisable avec UA + proxy aléatoires."""

    def __init__(self, options: dict | None = None):
        self.options = options or {}
        self.session = requests.Session()
        self._refresh_headers()

    def _refresh_headers(self) -> None:
        self.session.headers.update({
            'User-Agent': pick_user_agent(self.options),
            'Accept': 'text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8',
            'Accept-Language': 'fr-FR,fr;q=0.9,en;q=0.8',
        })

    def _apply_proxy(self) -> str | None:
        proxy = _pick_proxy(self.options)
        if proxy:
            self.session.proxies = {'http': proxy, 'https': proxy}
        else:
            self.session.proxies = {}
        return proxy

    def get(self, url: str, timeout: int = 15, **kwargs) -> requests.Response | None:
        proxy_used = self._apply_proxy()
        if self.options.get('_stealth_mode'):
            time.sleep(random.uniform(0.2, 1.2))
        try:
            return self.session.get(
                url, timeout=timeout, verify=SSL_VERIFY, **kwargs,
            )
        except requests.RequestException as e:
            if proxy_used:
                mark_proxy_dead(proxy_used)
                logger.debug('Proxy mort %s: %s', proxy_used[:40], e)
            return None

    def close(self) -> None:
        self.session.close()


def managed_get(url: str, options: dict | None = None, timeout: int = 15, **kwargs):
    """GET one-shot avec SessionManager."""
    mgr = SessionManager(options)
    try:
        return mgr.get(url, timeout=timeout, **kwargs)
    finally:
        mgr.close()
