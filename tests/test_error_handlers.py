"""Tests gestionnaires d'erreurs métier."""
import pytest
from flask import Flask

from services.errors import APIQuotaExceeded, AccessDeniedError, ValidationError
from services.error_handlers import register_error_handlers


@pytest.fixture
def err_app():
    app = Flask(__name__)
    register_error_handlers(app)

    @app.route('/test-quota')
    def _quota():
        raise APIQuotaExceeded(provider='shodan')

    @app.route('/test-access')
    def _access():
        raise AccessDeniedError('Dossier interdit')

    @app.route('/test-validation')
    def _validation():
        raise ValidationError('Champ invalide')

    return app


@pytest.fixture
def err_client(err_app):
    err_app.config['TESTING'] = True
    return err_app.test_client()


def test_quota_json(err_client):
    r = err_client.get('/test-quota', headers={'Accept': 'application/json'})
    assert r.status_code == 429
    data = r.get_json()
    assert data['code'] == 'quota_exceeded'
    assert data['provider'] == 'shodan'


def test_access_json(err_client):
    r = err_client.get('/test-access', headers={'Accept': 'application/json'})
    assert r.status_code == 403
    assert r.get_json()['code'] == 'access_denied'


def test_validation_json(err_client):
    r = err_client.get('/test-validation', headers={'Accept': 'application/json'})
    assert r.status_code == 400
    assert r.get_json()['code'] == 'validation_error'
