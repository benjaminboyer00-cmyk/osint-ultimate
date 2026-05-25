"""Helpers transaction SQLAlchemy."""
from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


def safe_commit(session, *, log: logging.Logger | None = None) -> None:
    """Commit avec rollback automatique en cas d'échec."""
    log = log or logger
    try:
        session.commit()
    except Exception:
        session.rollback()
        log.exception('Échec commit base de données')
        raise


def safe_commit_return(session, value: Any = None, *, log: logging.Logger | None = None) -> Any:
    safe_commit(session, log=log)
    return value
