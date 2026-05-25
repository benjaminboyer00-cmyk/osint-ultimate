"""Détection environnement (Hugging Face Spaces, limites ressources)."""
from __future__ import annotations

import os


def is_hf_space() -> bool:
    """Space Hugging Face (backend ou frontend)."""
    if os.environ.get('SPACE_ID') or os.environ.get('SYSTEM'):
        return True
    space_host = (os.environ.get('SPACE_HOST') or '').lower()
    return 'hf.space' in space_host


def instagram_instaloader_enabled() -> bool:
    """
    instaloader est lourd (RAM/CPU) — désactivé sur HF par défaut.
    OSINT_IG_MODE :
      - auto : instaloader hors HF, HTTP scrape sur HF
      - full : forcer instaloader (VPS / HF payant avec assez de RAM)
      - http : toujours HTTP scrape uniquement
    """
    mode = (os.environ.get('OSINT_IG_MODE') or 'auto').strip().lower()
    if mode == 'http':
        return False
    if mode == 'full':
        return True
    if mode == 'auto' and is_hf_space():
        return False
    return True


def use_celery_on_runtime() -> bool:
    """HF n'a en général pas de worker Celery — évite les tâches orphelines."""
    if is_hf_space():
        flag = (os.environ.get('USE_CELERY') or 'auto').strip().lower()
        if os.environ.get('OSINT_HF_CELERY', '').lower() in ('1', 'true', 'yes'):
            return flag not in ('0', 'false', 'no', 'off')
        return False
    return True  # laisser task_queue décider
