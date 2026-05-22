"""AlienVault OTX — indicateurs de compromission (IP, domaine)."""
import os
from connectors.base import BaseConnector

_connector = BaseConnector(name='otx', default_timeout=12, cache_ttl_hours=6)


def _fetch_indicator(indicator: str, indicator_type: str, api_key: str) -> dict:
    if not api_key:
        return {'Message': 'Clé OTX non configurée (OTX_API_KEY ou Paramètres)', 'configured': False}

    url = f'https://otx.alienvault.com/api/v1/indicators/{indicator_type}/{indicator}/general'
    resp = _connector._request(url, headers={'X-OTX-API-KEY': api_key})
    if resp is None:
        return {'_timeout': True, 'Message': 'OTX indisponible'}

    data = resp.json()
    pulse_info = data.get('pulse_info') or {}
    return {
        'indicator': indicator,
        'type': indicator_type,
        'reputation': pulse_info.get('reputation', 0),
        'pulse_count': pulse_info.get('count', 0),
        'references': (pulse_info.get('references') or [])[:10],
        'malware_families': (pulse_info.get('malware_families') or [])[:8],
        'tags': (pulse_info.get('tags') or [])[:15],
        'risk': 'élevé' if pulse_info.get('count', 0) > 0 else 'faible',
        'source': 'AlienVault OTX',
    }


def search(target: str, api_key: str = '', options=None) -> dict:
    target = (target or '').strip()
    opts = options or {}
    key = api_key or opts.get('_otx_key') or os.environ.get('OTX_API_KEY', '')

    if _looks_like_ip(target):
        ind_type = 'IPv4'
    else:
        ind_type = 'domain'
        if target.startswith('http'):
            from urllib.parse import urlparse
            target = urlparse(target).netloc or target

    def fetch():
        return _fetch_indicator(target, ind_type, key)

    data, source = _connector.get_cached_or_fetch(target, fetch, provider='otx')
    if isinstance(data, dict):
        data['_source'] = source
    return data


def _looks_like_ip(s: str) -> bool:
    import re
    return bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', s))
