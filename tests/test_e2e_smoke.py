"""Parcours smoke E2E (client Flask, sans navigateur)."""
import pytest


@pytest.fixture
def client():
    from app import app, db
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    with app.app_context():
        db.create_all()
        yield app.test_client()
        db.session.remove()
        db.drop_all()


def test_health_and_express(client):
    r = client.get('/health')
    assert r.status_code in (200, 503)
    assert 'Cache-Control' in r.headers
    r2 = client.get('/express')
    assert r2.status_code == 200


def test_register_login_flow(client):
    r = client.post('/register', data={
        'username': 'e2e_user_smoke',
        'email': 'e2e_smoke@example.com',
        'password': 'StrongPass2024!xyz',
    }, follow_redirects=False)
    assert r.status_code in (302, 200)
    r2 = client.post('/login', data={
        'username': 'e2e_user_smoke',
        'password': 'StrongPass2024!xyz',
    }, follow_redirects=False)
    assert r2.status_code in (302, 200)
