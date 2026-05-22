"""URLhaus (abuse.ch) — URLs et hôtes malveillants."""
from connectors.base import BaseConnector
from urllib.parse import urlparse

_connector = BaseConnector(name='urlhaus', default_timeout=10, cache_ttl_hours=6)


def _host_from_target(target: str) -> str:
    t = (target or '').strip()
    if t.startswith('http'):
        return urlparse(t).netloc or t
    return t.split('/')[0]


def search(target: str, options=None) -> dict:
    host = _host_from_target(target)
    if not host:
        return {'Erreur': 'Cible invalide'}

    def fetch():
        url = 'https://urlhaus-api.abuse.ch/v1/host/'
        resp = _connector._request(url, method='POST', data={'host': host})
        if resp is None:
            return {'_timeout': True, 'Message': 'URLhaus indisponible'}
        data = resp.json()
        if data.get('query_status') == 'no_results':
            return {
                'host': host,
                'listed': False,
                'url_count': 0,
                'risk': 'faible',
                'message': 'Aucune URL malveillante répertoriée pour cet hôte',
                'source': 'URLhaus abuse.ch',
            }
        if data.get('query_status') != 'ok':
            return {'Erreur': data.get('query_status', 'erreur URLhaus')}

        urls = data.get('urls') or []
        threats = list({u.get('threat') for u in urls if u.get('threat')})[:5]
        return {
            'host': host,
            'listed': True,
            'url_count': data.get('url_count', len(urls)),
            'blacklists': data.get('blacklists') or {},
            'threat_types': threats,
            'sample_urls': [u.get('url') for u in urls[:5] if u.get('url')],
            'risk': 'élevé' if urls else 'faible',
            'source': 'URLhaus abuse.ch',
        }

    data, source = _connector.get_cached_or_fetch(host, fetch, provider='urlhaus')
    if isinstance(data, dict):
        data['_source'] = source
    return data
