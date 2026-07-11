"""Tests livrable blindé — Phase 4 V7."""
import sys
from unittest.mock import MagicMock, patch

from services.report_builder import _section_status, build_traceability
from services.report_seal import (
    verify_uploaded_pdf,
    seal_scan_report,
    qr_code_data_uri,
    verify_page_url,
    sha256_bytes,
)
from services.report_signing import sign_bytes


def test_section_status_fallback():
    assert _section_status({'_degraded': True}) == 'fallback'
    assert _section_status({'_source': 'scraping_fallback'}) == 'fallback'
    assert _section_status({'_cached': True}) == 'cache'
    assert _section_status({'_timeout': True}) == 'timeout'
    assert _section_status({'ok': 1}) == 'succès'


def test_traceability_has_statut():
    scan = MagicMock(
        id=1, module='email', target='a@b.com',
        timestamp=None, completed_at=None,
    )
    chain = build_traceability(scan, {'Module: email': {'MX': 'x'}})
    assert chain[0]['statut'] == 'succès'
    assert 'statut' in chain[1]


def test_verify_uploaded_pdf_match():
    data = b'%PDF-1.4 fake'
    sig = sign_bytes(data)   # sceau = signature HMAC des octets
    scan = MagicMock(report_pdf_hash=sig, report_sealed_at=None)
    out = verify_uploaded_pdf(data, scan)
    assert out['valid'] is True


def test_verify_rejects_sha256_only_seal():
    """Un simple SHA-256 stocké ne doit PAS valider (il faut la signature HMAC)."""
    data = b'%PDF-1.4 fake'
    scan = MagicMock(report_pdf_hash=sha256_bytes(data), report_sealed_at=None)
    assert verify_uploaded_pdf(data, scan)['valid'] is False


def test_verify_uploaded_pdf_no_seal():
    scan = MagicMock(report_pdf_hash=None, report_sealed_at=None)
    out = verify_uploaded_pdf(b'%PDF', scan)
    assert out['valid'] is False


def test_verify_uploaded_pdf_tampered():
    scan = MagicMock(report_pdf_hash='abc', report_sealed_at=None)
    out = verify_uploaded_pdf(b'%PDF-other', scan)
    assert out['valid'] is False


def test_qr_data_uri():
    fake_img = MagicMock()
    fake_img.save = lambda buf, format=None: buf.write(b'png')
    fake_mod = MagicMock()
    fake_mod.QRCode.return_value.make_image.return_value = fake_img
    with patch.dict(sys.modules, {'qrcode': fake_mod}):
        uri = qr_code_data_uri('https://example.com/verify/42')
    assert uri.startswith('data:image/png;base64,')


def test_verify_page_url():
    url = verify_page_url(7, 'https://test.hf.space')
    assert url == 'https://test.hf.space/verify/7'


def test_seal_scan_report_signs_bytes():
    data = b'%PDF-1.4 final'
    scan = MagicMock(report_pdf_hash=None, report_sealed_at=None)
    with patch('extensions.db') as mock_db:
        seal_scan_report(scan, data)
    assert scan.report_pdf_hash == sign_bytes(data)   # HMAC, pas un simple hash
    mock_db.session.add.assert_called_with(scan)
