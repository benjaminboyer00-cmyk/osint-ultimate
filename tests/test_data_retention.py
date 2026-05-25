"""Tests politique de rétention."""
import os
import time
from datetime import datetime, timedelta
from pathlib import Path

from services.data_retention import purge_uploads, purge_api_cache_expired


def test_purge_uploads_removes_old_files(tmp_path, monkeypatch):
    monkeypatch.setenv('UPLOAD_FOLDER', str(tmp_path))
    old = tmp_path / 'old.pdf'
    old.write_bytes(b'x')
    old_time = time.time() - (40 * 86400)
    os.utime(old, (old_time, old_time))
    new = tmp_path / 'new.pdf'
    new.write_bytes(b'y')

    out = purge_uploads(max_age_days=30)
    assert out['ok'] is True
    assert out['removed_files'] >= 1
    assert not old.exists()
    assert new.exists()


def test_purge_api_cache_expired(app):
    from extensions import db
    from models import ApiCache

    past = datetime.utcnow() - timedelta(days=1)
    future = datetime.utcnow() + timedelta(days=1)
    db.session.add(ApiCache(
        provider='test', cache_key='k1', query='q',
        payload='{}', expires_at=past,
    ))
    db.session.add(ApiCache(
        provider='test', cache_key='k2', query='q',
        payload='{}', expires_at=future,
    ))
    db.session.commit()

    out = purge_api_cache_expired()
    assert out['ok'] is True
    assert out['removed_rows'] >= 1
    remaining = db.session.query(ApiCache).filter_by(cache_key='k2').first()
    assert remaining is not None
