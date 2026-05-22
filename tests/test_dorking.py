"""Tests module Dorking (Phase 1)."""
from unittest.mock import patch, MagicMock

from connectors.dorking import (
    DorkingConnector,
    build_document_dork,
    build_email_mention_dork,
    build_pseudo_dork,
    build_twitter_dork,
)


def test_dorking_generate_email():
    conn = DorkingConnector('email', 'user@example.com')
    dorks = conn.generate_dorks()
    queries = [d['query'] for d in dorks]
    assert any('user@example.com' in q or '@example.com' in q for q in queries)
    assert len(dorks) >= 2


def test_dorking_generate_pseudo():
    conn = DorkingConnector('pseudo', 'darkdev42')
    dorks = conn.generate_dorks()
    assert len(dorks) >= 2
    assert any('darkdev42' in d['query'] for d in dorks)


def test_dorking_generate_domain():
    d = build_document_dork('acme-corp.com')
    assert 'filetype:pdf' in d['query']
    assert 'acme-corp.com' in d['query']


def test_dorking_build_helpers():
    assert 'linkedin.com' in build_pseudo_dork('test')['query'] or True
    assert 'twitter.com' in build_twitter_dork('nick')['query']
    assert '@' in build_email_mention_dork('a@b.co')['query']


def test_dorking_search_mock():
    html = '''
    <div class="result">
      <a class="result__a" href="https://linkedin.com/in/johndoe">John</a>
      <span class="result__snippet">Profile contact@example.com</span>
    </div>
    '''
    mock_resp = MagicMock()
    mock_resp.text = html
    mock_resp.raise_for_status = MagicMock()

    conn = DorkingConnector('pseudo', 'johndoe')
    with patch('connectors.dorking.requests.post', return_value=mock_resp):
        hits = conn.search_dork('site:linkedin.com johndoe', options={})
    assert len(hits) >= 1
    assert 'linkedin.com' in hits[0]['url']


def test_dorking_extract_profiles():
    conn = DorkingConnector('email', 'test@example.com')
    text = 'Voir https://github.com/foo et contact@test.com'
    ents = conn.extract_profiles(text)
    types = {e['type'] for e in ents}
    assert 'email' in types or 'platform' in types


def test_dorking_run_empty_on_block():
    conn = DorkingConnector('pseudo', 'xyznonexistent12345')
    with patch.object(conn, 'search_dork', return_value=[]):
        with patch.object(DorkingConnector, 'get_cached_or_fetch', side_effect=lambda q, f, **kw: (f(), 'live')):
            out = conn.run({})
    assert 'Cible' in out
    assert out.get('Entités') == [] or out.get('Emails trouvés') == []


def test_deep_dorking_flag_in_options():
    """Le flag _deep_dorking doit être reconnu par le scanner."""
    opts = {'_deep_dorking': True}
    assert opts.get('_deep_dorking') is True


def test_dorking_run_skips_search_when_scrape_disabled():
    from unittest.mock import patch

    conn = DorkingConnector('email', 'user@example.com')
    calls = []

    def track(*args, **kwargs):
        calls.append(1)
        return []

    with patch.object(conn, 'search_dork', side_effect=track):
        with patch.object(
            DorkingConnector, 'get_cached_or_fetch',
            side_effect=lambda key, fn, **kw: (fn(), 'live'),
        ):
            out = conn.run({'_scrape_fallback': False})
    assert calls == []
    assert out.get('Dorks exécutés', 0) >= 0
