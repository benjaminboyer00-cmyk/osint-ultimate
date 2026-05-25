"""Tests environnement HF / Instagram mode."""
import os
from unittest.mock import patch

from services.runtime_env import (
    instagram_instaloader_enabled,
    is_hf_space,
    use_celery_on_runtime,
)


def test_is_hf_space():
    with patch.dict(os.environ, {'SPACE_ID': 'benji/test'}, clear=False):
        assert is_hf_space() is True


def test_instaloader_disabled_on_hf_auto():
    with patch.dict(os.environ, {'SPACE_ID': 'x', 'OSINT_IG_MODE': 'auto'}, clear=False):
        assert instagram_instaloader_enabled() is False


def test_instaloader_full_mode():
    with patch.dict(os.environ, {'SPACE_ID': 'x', 'OSINT_IG_MODE': 'full'}, clear=False):
        assert instagram_instaloader_enabled() is True


def test_celery_off_on_hf():
    with patch.dict(os.environ, {'SPACE_ID': 'x'}, clear=False):
        assert use_celery_on_runtime() is False
