"""Registre des scans — extraction depuis app.py."""
from scans.registry import CORE_SCAN_FUNCTIONS, SCAN_FUNCTIONS


def test_core_scan_modules_registered():
    for mod in ('site', 'email', 'phone', 'ip', 'instagram', 'multi'):
        assert mod in SCAN_FUNCTIONS
    assert 'hunter' in SCAN_FUNCTIONS
    assert len(CORE_SCAN_FUNCTIONS) >= 12


def test_scan_site_callable():
    from scans.core_scans import scan_site
    assert callable(scan_site)
