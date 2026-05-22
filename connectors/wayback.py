"""Archive.org Wayback Machine."""
from urllib.parse import quote

from services.cache import get_cached, set_cached, get_ttl_hours
from services.http_client import safe_get


def search_url(url: str, options=None, limit: int = 10) -> dict:
    target = url.strip()
    if not target.startswith('http'):
        target = f'https://{target}'
    domain = target.split('//')[-1].split('/')[0].lower().replace('www.', '')

    cached = get_cached('wayback', domain)
    if cached:
        cached['_cached'] = True
        return cached

    opts = dict(options or {})
    opts['_retry'] = True
    cdx_url = (
        'https://web.archive.org/cdx/search/cdx'
        f'?url={quote(domain + "/*", safe="")}'
        f'&output=json&limit={limit}'
        '&fl=timestamp,original,statuscode&collapse=urlkey'
    )
    snaps = safe_get(cdx_url, timeout=30, options=opts)
    results = {'URL': target, 'Domaine': domain}
    if snaps and snaps.status_code == 200:
        try:
            data = snaps.json()
            if len(data) > 1:
                results['Snapshots'] = [
                    {
                        'Date': row[0][:8],
                        'URL': row[1],
                        'Statut': row[2] if len(row) > 2 else '',
                        'Lien archive': f'https://web.archive.org/web/{row[0]}/{row[1]}',
                    }
                    for row in data[1:]
                ]
                results['Total archivé'] = len(results['Snapshots'])
            else:
                results['Snapshots'] = 'Aucun snapshot trouvé'
        except Exception as e:
            results['Erreur'] = str(e)
    elif snaps and snaps.status_code == 429:
        results['Erreur'] = 'Wayback — trop de requêtes (429). Réessayez plus tard.'
        results['_timeout'] = True
    else:
        code = snaps.status_code if snaps else 'timeout'
        results['Erreur'] = f'Wayback inaccessible ({code}). Vérifiez le domaine ou réessayez.'
        results['_timeout'] = True

    if not results.get('Erreur'):
        set_cached('wayback', domain, results, ttl_hours=get_ttl_hours('wayback'))
    return results
