"""Tests filtrage entités Dorking."""
from services.dorking_filter import (
    filter_dorking_entities,
    is_relevant_entity,
    extract_profile_handle,
)


def test_reject_unrelated_github_for_email_target():
    assert not is_relevant_entity(
        'https://github.com/benjamin.boyer00',
        'platform',
        'user@example.com',
        'email',
        confidence=0.55,
    )


def test_accept_github_matching_local_part():
    assert is_relevant_entity(
        'https://github.com/user',
        'platform',
        'user@example.com',
        'email',
        confidence=0.55,
    )


def test_filter_dorking_entities_dedup():
    raw = [
        {'type': 'platform', 'value': 'https://github.com/other', 'confidence': 0.55},
        {'type': 'email', 'value': 'user@example.com', 'confidence': 0.5},
        {'type': 'email', 'value': 'user@example.com', 'confidence': 0.5},
    ]
    out = filter_dorking_entities(raw, 'user@example.com', 'email')
    assert len(out) == 1
    assert out[0]['value'] == 'user@example.com'


def test_extract_profile_handle():
    assert extract_profile_handle('https://github.com/foo/bar') == 'foo'
    assert 'jane' in extract_profile_handle('https://www.linkedin.com/in/jane-doe')
