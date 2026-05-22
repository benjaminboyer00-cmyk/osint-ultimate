"""Tests connecteurs, fallback scraping, mode enquête graphe."""
import pytest
from unittest.mock import patch, MagicMock


def test_no_apicache_query_antipattern():
    """Régression : pas d'appel ORM ApiCache.query.* (colonne SQL `query` masque Model.query)."""
    import pathlib
    import re

    root = pathlib.Path(__file__).resolve().parents[1]
    usage = re.compile(r'ApiCache\.query\.(filter|get|first|all|count|one)')
    bad = []
    for path in root.rglob('*.py'):
        if 'migrations' in path.parts or '.venv' in path.parts or path.name == 'test_connectors.py':
            continue
        for line in path.read_text(encoding='utf-8', errors='ignore').splitlines():
            code = line.split('#', 1)[0]
            if usage.search(code):
                bad.append(f'{path.relative_to(root)}: {line.strip()[:80]}')
                break
    assert bad == [], f'Utiliser db.session.query(ApiCache): {bad}'


def test_scan_strategies_include_enrichment_modules():
    from services.scanner import SCAN_STRATEGIES, EXPRESS_STRATEGIES
    assert 'dehashed' in SCAN_STRATEGIES['email']
    assert 'hunter' in SCAN_STRATEGIES['email']
    assert 'epieos' in SCAN_STRATEGIES['email']
    assert 'wayback' in SCAN_STRATEGIES['domain']
    assert 'hunter' in EXPRESS_STRATEGIES['domain']
    assert 'dehashed' in EXPRESS_STRATEGIES['email']


def test_scraper_fallback_timeout():
    """DDG en échec → liste vide, pas d'exception."""
    with patch('connectors.scraper_fallback.requests.post', side_effect=TimeoutError('timeout')):
        with patch('connectors.scraper_fallback.fetch_url_protected', return_value=None):
            from connectors.scraper_fallback import fallback_scrape_emails
            out = fallback_scrape_emails('example.com', {})
    assert out == []


def test_scraper_fallback_disabled_by_policy():
    from services.scrape_policy import scrape_fallback_allowed
    assert scrape_fallback_allowed({'_scrape_fallback': False}) is False
    assert scrape_fallback_allowed({}) is True


def test_cloudscraper_cache_reuses_session_for_same_proxy():
    """Évite une nouvelle instance cloudscraper par id(dict) à chaque appel."""
    import connectors.scraper_fallback as sf
    from unittest.mock import MagicMock, patch

    sf._scraper_cache.clear()
    mock_scraper = MagicMock()
    with patch('cloudscraper.create_scraper', return_value=mock_scraper) as create:
        a = sf._get_cloudscraper({'_proxy_list': 'http://proxy:8080'})
        b = sf._get_cloudscraper({'_proxy_list': 'http://proxy:8080'})
    assert a is b
    assert create.call_count == 1
    sf._scraper_cache.clear()


def test_quota_error_detection():
    from services.quota_fallback import is_quota_error
    assert is_quota_error({'Erreur': 'HTTP 429 quota', '_quota': True})
    assert not is_quota_error({'Liste': [], 'Emails trouvés': 0})


def test_graph_enquiry_suggestions():
    """Suggestion du nœud le plus prometteur (faible confiance = priorité)."""
    with patch('services.graph_enquiry.Entity') as Ent, \
         patch('services.graph_enquiry.EntityLink') as Link, \
         patch('services.graph_enquiry.db') as db:

        root = MagicMock(id=1, entity_type='email', value='a@test.com')
        other = MagicMock(id=2, entity_type='domain', value='test.com')
        Ent.query.filter_by.return_value.first.return_value = root
        db.session.get.return_value = other

        link = MagicMock(
            source_id=1, target_id=2, confidence=0.2,
            link_type='same_domain', user_id=10,
        )
        Link.query.filter.return_value.all.return_value = [link]
        Link.query.filter.return_value.count.return_value = 0

        from services.graph_enquiry import suggest_next_node
        sug = suggest_next_node(1, 10)

    assert sug is not None
    assert sug['entity_id'] == 2
    assert sug['module'] in ('whois', 'email', 'sherlock', 'ip')
    assert 'score' in sug
    assert sug['confidence'] == 0.2
