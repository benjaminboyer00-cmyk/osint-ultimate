"""Tests parsing social."""
from services.social_fetch import profile_exists_in_html


def test_profile_exists_in_html():
    html = '<meta property="og:url" content="https://www.instagram.com/alice/">'
    assert profile_exists_in_html(html, 'alice') is True


def test_profile_not_found_page():
    html = 'Sorry, this page isn\'t available. instagram.com/missing'
    assert profile_exists_in_html(html, 'missing') is False
