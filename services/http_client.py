"""Client HTTP unifié — proxies, mode furtif, cache."""
import os
import random
import time
import requests

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
]


def _proxy_list(options: dict | None) -> list:
    opts = options or {}
    if opts.get('_proxy_list'):
        return [p.strip() for p in opts['_proxy_list'].split(',') if p.strip()]
    env = os.environ.get('PROXY_LIST', '')
    return [p.strip() for p in env.split(',') if p.strip()]


def safe_get(url, timeout=15, options=None, **kwargs):
    opts = options or {}
    if opts.get('_module_timeout'):
        timeout = min(timeout, int(opts['_module_timeout']))
    if opts.get('_retry'):
        timeout = max(timeout, 20)
    if opts.get('_stealth_mode'):
        time.sleep(random.uniform(0.3, 1.8))
    try:
        s = requests.Session()
        ua = random.choice(USER_AGENTS) if opts.get('_stealth_mode') else USER_AGENTS[0]
        s.headers.update({'User-Agent': ua})
        proxies = _proxy_list(opts)
        if proxies:
            p = random.choice(proxies)
            s.proxies = {'http': p, 'https': p}
        return s.get(url, timeout=timeout, verify=False, **kwargs)
    except requests.Timeout:
        return None
    except Exception:
        return None
