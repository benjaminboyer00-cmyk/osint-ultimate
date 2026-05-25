"""Infos runtime publiques pour le frontend (bannière HF, statut)."""
from __future__ import annotations

import os

from services.runtime_env import instagram_instaloader_enabled, is_hf_space, use_celery_on_runtime


def public_runtime_info() -> dict:
    hf = is_hf_space()
    ig_full = instagram_instaloader_enabled()
    return {
        'hf_space': hf,
        'socket_io': not hf,
        'celery': use_celery_on_runtime() and bool(os.environ.get('REDIS_URL')),
        'instagram_mode': 'full' if ig_full else ('http' if hf else 'auto'),
        'version': os.environ.get('APP_VERSION', '5.2'),
        'hint': (
            'Démo Hugging Face : scans en file thread, temps réel via polling. '
            'Instagram / médias complets et Celery → VPS.'
            if hf
            else None
        ),
    }
