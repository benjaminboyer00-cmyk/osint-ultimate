"""Sauvegardes DB PostgreSQL et dossier uploads."""
from __future__ import annotations

import logging
import os
import shutil
import subprocess
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

BACKUP_DIR = Path(os.environ.get('BACKUP_DIR', '/code/backups'))


def _ensure_backup_dir() -> Path:
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    return BACKUP_DIR


def _pg_dump_url(url: str) -> str:
    """Normalise l'URL SQLAlchemy pour pg_dump."""
    u = url.replace('postgresql+psycopg2://', 'postgresql://')
    u = u.replace('postgres://', 'postgresql://')
    return u


def backup_database() -> dict:
    """
    Dump PostgreSQL via pg_dump si DATABASE_URL est postgres.
    Retourne {ok, path, error}.
    """
    db_url = os.environ.get('DATABASE_URL', '')
    if not db_url or 'postgres' not in db_url.lower():
        return {'ok': False, 'skipped': True, 'reason': 'DATABASE_URL non PostgreSQL'}

    out_dir = _ensure_backup_dir()
    stamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    out_path = out_dir / f'db_{stamp}.sql.gz'

    try:
        proc = subprocess.run(
            ['pg_dump', _pg_dump_url(db_url), '--no-owner', '--no-acl'],
            capture_output=True,
            check=True,
            timeout=600,
        )
        import gzip
        with gzip.open(out_path, 'wb') as f:
            f.write(proc.stdout)
        logger.info('Backup DB: %s (%s bytes)', out_path, out_path.stat().st_size)
        _prune_old_backups(out_dir, 'db_', keep=int(os.environ.get('BACKUP_KEEP_DAYS', '7')))
        return {'ok': True, 'path': str(out_path), 'size': out_path.stat().st_size}
    except FileNotFoundError:
        return {'ok': False, 'error': 'pg_dump introuvable — installez postgresql-client'}
    except subprocess.CalledProcessError as e:
        return {'ok': False, 'error': (e.stderr or b'').decode()[:500]}
    except Exception as e:
        logger.exception('backup_database')
        return {'ok': False, 'error': str(e)}


def backup_uploads() -> dict:
    """Archive le dossier uploads/."""
    upload_root = Path(os.environ.get('UPLOAD_FOLDER', 'uploads'))
    if not upload_root.is_dir():
        return {'ok': False, 'skipped': True, 'reason': 'dossier uploads absent'}

    out_dir = _ensure_backup_dir()
    stamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    archive_base = out_dir / f'uploads_{stamp}'
    try:
        archive_path = shutil.make_archive(str(archive_base), 'gztar', str(upload_root.parent), upload_root.name)
        logger.info('Backup uploads: %s', archive_path)
        _prune_old_backups(out_dir, 'uploads_', keep=int(os.environ.get('BACKUP_KEEP_DAYS', '7')))
        return {'ok': True, 'path': archive_path}
    except Exception as e:
        logger.exception('backup_uploads')
        return {'ok': False, 'error': str(e)}


def run_all_backups() -> dict:
    """DB + uploads — appelé par Celery beat ou cron."""
    return {
        'database': backup_database(),
        'uploads': backup_uploads(),
        'at': datetime.utcnow().isoformat() + 'Z',
    }


def _prune_old_backups(directory: Path, prefix: str, keep: int) -> None:
    """Conserve les N derniers fichiers par préfixe."""
    files = sorted(directory.glob(f'{prefix}*'), key=lambda p: p.stat().st_mtime, reverse=True)
    for old in files[keep:]:
        try:
            old.unlink()
        except OSError:
            pass
