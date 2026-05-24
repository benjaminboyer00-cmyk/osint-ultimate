"""
Configuration pytest globale.

IMPORTANT : les tests n'utilisent JAMAIS Supabase sauf si
  OSINT_TEST_USE_DATABASE_URL=1 est défini.

Pour les migrations : utilisez `flask db upgrade` dans un shell séparé
(sans lancer pytest juste après avoir exporté DATABASE_URL si vous voulez
éviter la confusion — ou ouvrez deux terminaux).
"""
from __future__ import annotations

import os
import warnings

import pytest

# Avant tout import de app.py
if os.environ.get('OSINT_TEST_USE_DATABASE_URL') != '1':
    os.environ['DATABASE_URL'] = 'sqlite:///:memory:'
elif 'supabase' in (os.environ.get('DATABASE_URL') or '').lower():
    warnings.warn(
        'OSINT_TEST_USE_DATABASE_URL=1 : les tests modifient la vraie base !',
        stacklevel=1,
    )


@pytest.fixture
def app():
    from app import app as flask_app
    from tests.db_utils import clear_all_rows
    from extensions import db

    flask_app.config['TESTING'] = True
    flask_app.config['WTF_CSRF_ENABLED'] = False
    if os.environ.get('OSINT_TEST_USE_DATABASE_URL') != '1':
        flask_app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'

    with flask_app.app_context():
        db.create_all()
        yield flask_app
        try:
            clear_all_rows(db)
        except Exception:
            db.session.rollback()
        db.session.remove()


@pytest.fixture
def client(app):
    return app.test_client()
