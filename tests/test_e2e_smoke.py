"""Parcours smoke E2E (client Flask, sans navigateur)."""
import uuid

import pytest


def test_health_and_express(client):
    r = client.get('/health')
    assert r.status_code in (200, 503)
    assert 'Cache-Control' in r.headers
    r2 = client.get('/express')
    assert r2.status_code == 200


def test_register_login_flow(client):
    suffix = uuid.uuid4().hex[:8]
    username = f'e2e_smoke_{suffix}'
    r = client.post('/register', data={
        'username': username,
        'email': f'{username}@example.com',
        'password': 'StrongPass2024!xyz',
    }, follow_redirects=False)
    assert r.status_code in (302, 200)
    r2 = client.post('/login', data={
        'username': username,
        'password': 'StrongPass2024!xyz',
    }, follow_redirects=False)
    assert r2.status_code in (302, 200)


def test_weak_password_rejected(client):
    r = client.post('/register', data={
        'username': f'weak_{uuid.uuid4().hex[:8]}',
        'email': 'weak@example.com',
        'password': '123',
    }, follow_redirects=True)
    assert r.status_code == 200
    assert b'faible' in r.data.lower() or b'court' in r.data.lower() or b'requis' in r.data.lower()


def test_password_strength_api(client):
    r = client.post('/api/password-strength', json={'password': 'MySecurePass2024!'})
    assert r.status_code == 200
    data = r.get_json()
    assert 'score' in data
    assert 'acceptable' in data


def test_static_cache_headers(client):
    r = client.get('/static/css/style.css')
    if r.status_code == 404:
        pytest.skip('fichier static absent')
    assert 'Cache-Control' in r.headers


def test_openapi_docs(client):
    r = client.get('/api/v1/docs')
    assert r.status_code == 200
    data = r.get_json()
    assert data.get('openapi') == '3.0.0'
