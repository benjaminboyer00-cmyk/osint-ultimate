"""Archive.org Wayback Machine."""
from services.cache import get_cached, set_cached, get_ttl_hours
from services.http_client import safe_get


def search_url(url: str, options=None, limit: int = 10) -> dict:
    target = url.strip()
    if not target.startswith('http'):
        target = f'https://{target}'
    domain = target.split('//')[-1].split('/')[0]

    cached = get_cached('wayback', domain)
    if cached:
        cached['_cached'] = True
        return cached

    snaps = safe_get(
        f'https://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&limit={limit}'
        f'&fl=timestamp,original,statuscode&collapse=urlkey',
        options=options,
    )
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
    else:
        results['Erreur'] = 'Wayback Machine inaccessible'

    set_cached('wayback', domain, results, ttl_hours=get_ttl_hours('wayback'))
    return results
