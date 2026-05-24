"""Tests cache manager et tâches async (sans Redis requis)."""
import json
from unittest.mock import MagicMock, patch

from services.cache_manager import _redis_key, ttl_seconds
from services.async_tasks import get_job, _save_job


def test_redis_key_format():
    k = _redis_key('hunter', 'example.com')
    assert k.startswith('lookup:hunter:')


def test_ttl_seconds_whois():
    assert ttl_seconds('whois') >= 3600


def test_job_memory_store():
    _save_job('test-task-1', {'status': 'pending', 'entity_id': 1})
    job = get_job('test-task-1')
    assert job is not None
    assert job['status'] == 'pending'


def test_suggestions_structure():
    with patch('services.osint_suggestions.get_rebound_suggestions', return_value=[]):
        with patch('services.osint_suggestions.build_report_data', return_value=None):
            from services.osint_suggestions import suggest_investigation_steps
            out = suggest_investigation_steps(1, 10)
    assert isinstance(out, list)
