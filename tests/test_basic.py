"""Tests unitaires de base."""
import pytest
from services.target_detector import detect_target_type
from services.express_card import build_express_card


def test_detect_email():
    assert detect_target_type('test@example.com') == 'email'


def test_detect_ip():
    assert detect_target_type('8.8.8.8') == 'ip'


def test_detect_phone():
    assert detect_target_type('+33612345678') == 'phone'


def test_express_card_ok():
    card = build_express_card('phone', '+33600000000', {'Pays': 'France', 'Valide': '✓ Oui'})
    assert card['status'] == 'ok'
    assert len(card['highlights']) >= 1


def test_correlation_links_structure():
    from services.correlation import build_entity_links_json
    assert callable(build_entity_links_json)
