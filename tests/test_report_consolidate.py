"""Tests consolidation rapport et faits techniques."""
from unittest.mock import MagicMock

from services.report_consolidate import (
    consolidate_scan_payloads,
    extract_technical_facts,
    _canonical_key,
    _section_score,
)


def test_canonical_key_whois():
    assert _canonical_key('Domaine WHOIS') == 'WHOIS'
    assert _canonical_key('WHOIS (scan #19)') == 'WHOIS'


def test_section_score_prefers_complete():
    assert _section_score({'Registrar': 'X', 'Pays': 'FR'}) > _section_score({'Erreur': 'timeout'})
    assert _section_score({'Erreur': 'fail'}) < _section_score({'A': ['1.2.3.4']})


def test_extract_technical_facts():
    data = {
        'WHOIS': {'Registrar': 'OVH', 'Pays': 'FR'},
        'DNS': {'A': ['1.2.3.4'], 'MX': ['mx.example.com']},
        'IP': '1.2.3.4',
        'Géolocalisation': {'Ville': 'Paris', 'Pays': 'France', 'FAI': 'AWS'},
        'Hunter': {'_not_executed': True, 'Raison': 'Clé API Hunter manquante'},
    }
    facts = extract_technical_facts(data, 'example.com')
    assert facts['cible'] == 'example.com'
    assert len(facts['infrastructure']) >= 1
    assert len(facts['reseau']) >= 1
    assert any('Hunter' in x for x in facts['lacunes'])


def test_consolidate_dedup_whois():
    """Deux scans WHOIS → une seule section."""
    from unittest.mock import MagicMock, patch
    s1 = MagicMock(
        id=1, module='site', target='example.com', status='completed',
        timestamp=None, completed_at=None, result_json='{"WHOIS": {"Registrar": "A"}}',
    )
    s2 = MagicMock(
        id=2, module='whois', target='example.com', status='completed',
        timestamp=None, completed_at=None,
        result_json='{"WHOIS": {"Registrar": "B", "Pays": "FR", "Création": "2020"}}',
    )
    ctx = {'owner_user_id': 10, 'entity': MagicMock(id=1)}
    q = MagicMock()
    q.order_by.return_value.limit.return_value.all.return_value = [s1, s2]
    with patch('services.dossier_access.get_dossier_context', return_value=ctx):
        with patch('services.report_consolidate.Scan') as Scan:
            Scan.query.filter.return_value = q
            out = consolidate_scan_payloads(1, 10, 'example.com')
    assert 'WHOIS' in out
    assert 'WHOIS (scan' not in ''.join(out.keys())
    whois = out['WHOIS']
    assert whois.get('Registrar') == 'B' or whois.get('Pays') == 'FR'
