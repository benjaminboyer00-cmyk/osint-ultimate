"""Tests WHOIS RDAP (sans réseau si mock)."""
from unittest.mock import patch

from connectors.whois_domain import lookup, _normalize_domain, _rdap_usable


def test_normalize_domain():
    assert _normalize_domain('https://WWW.Example.COM/x') == 'example.com'


def test_rdap_usable():
    assert _rdap_usable({'Registrar': 'OVH', 'Pays': 'FR'}) is True
    assert _rdap_usable({'Erreur': 'x'}) is False


def test_lookup_whoisit_mock():
    with patch('connectors.whois_domain._lookup_whoisit', return_value={
        'Domaine': 'example.com', 'Registrar': 'Test Registrar', 'Pays': 'US',
        'Création': '2020-01-01', 'Expiration': 'N/A', 'Dernière MAJ': 'N/A',
        'Statut': 'active', 'Organisation': 'N/A', '_source': 'whoisit-rdap',
    }):
        with patch('connectors.whois_domain._lookup_rdap', return_value=None):
            with patch('connectors.whois_domain._lookup_domainsdb', return_value=None):
                with patch('services.cache.get_cached', return_value=None):
                    with patch('services.cache.set_cached'):
                        out = lookup('example.com')
    assert out.get('Registrar') == 'Test Registrar'
    assert out.get('executed') is True
