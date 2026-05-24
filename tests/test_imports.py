"""Vérifie que les modules critiques s'importent (SyntaxError, ImportError)."""
import importlib

import pytest

CRITICAL_MODULES = [
    'services.report_consolidate',
    'services.report_data',
    'services.narrative_api',
    'services.narrative_report',
    'services.dossier_access',
    'services.collaboration',
    'services.social_fetch',
    'services.url_sanitize',
    'services.dossier_scans',
    'routes.views',
    'connectors.scraper_fallback',
]


@pytest.mark.parametrize('module_name', CRITICAL_MODULES)
def test_critical_module_imports(module_name):
    importlib.import_module(module_name)


def test_extract_technical_facts_ssl_valid_until():
    from services.report_consolidate import extract_technical_facts
    data = {
        'SSL/TLS': {
            'Émetteur': "Let's Encrypt",
            "Valide jusqu'au": '2026-01-01',
        },
    }
    facts = extract_technical_facts(data, 'example.com')
    assert facts['securite']
    assert '2026' in facts['securite'][0]
