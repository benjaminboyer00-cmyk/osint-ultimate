"""Tests couche LLM multi-fournisseur (Phase 3 — robustesse)."""
from unittest.mock import patch, MagicMock

import pytest

import services.llm as llm


def _resp(content, status=200):
    m = MagicMock()
    m.status_code = status
    m.text = '' if status == 200 else 'boom'
    m.json.return_value = {'choices': [{'message': {'content': content}}]} if content else {'choices': []}
    return m


@pytest.fixture(autouse=True)
def _clear_cache():
    llm._CACHE.clear()
    yield
    llm._CACHE.clear()


def test_no_provider_raises(monkeypatch):
    for p in llm.PROVIDERS:
        monkeypatch.delenv(p['key_env'], raising=False)
    with pytest.raises(ValueError):
        llm.llm_chat([{'role': 'user', 'content': 'hi'}], use_cache=False)


def test_falls_back_to_second_provider(monkeypatch):
    monkeypatch.setenv('GROQ_API_KEY', 'k1')
    monkeypatch.setenv('GEMINI_API_KEY', 'k2')
    for p in ('CEREBRAS_API_KEY', 'OPENROUTER_API_KEY'):
        monkeypatch.delenv(p, raising=False)

    calls = []

    def fake_post(url, **kw):
        calls.append(url)
        if 'groq.com' in url:
            return _resp(None, status=429)  # rate-limited
        return _resp('depuis gemini')

    with patch('services.llm.requests.post', side_effect=fake_post):
        out = llm.llm_chat([{'role': 'user', 'content': 'hi'}], use_cache=False)
    assert out == 'depuis gemini'
    assert any('groq.com' in u for u in calls)
    assert any('googleapis' in u for u in calls)


def test_all_fail_raises_runtime(monkeypatch):
    monkeypatch.setenv('GROQ_API_KEY', 'k1')
    for p in ('GEMINI_API_KEY', 'CEREBRAS_API_KEY', 'OPENROUTER_API_KEY'):
        monkeypatch.delenv(p, raising=False)
    with patch('services.llm.requests.post', return_value=_resp(None, status=500)):
        with pytest.raises(RuntimeError):
            llm.llm_chat([{'role': 'user', 'content': 'hi'}], use_cache=False)


def test_cache_avoids_second_call(monkeypatch):
    monkeypatch.setenv('GROQ_API_KEY', 'k1')
    with patch('services.llm.requests.post', return_value=_resp('cached!')) as post:
        msgs = [{'role': 'user', 'content': 'même prompt'}]
        a = llm.llm_chat(msgs)
        b = llm.llm_chat(msgs)
    assert a == b == 'cached!'
    assert post.call_count == 1  # 2e appel servi par le cache


def test_provider_order_env(monkeypatch):
    monkeypatch.setenv('GROQ_API_KEY', 'k1')
    monkeypatch.setenv('GEMINI_API_KEY', 'k2')
    monkeypatch.setenv('LLM_PROVIDER_ORDER', 'gemini,groq')
    names = [p['name'] for p in llm._configured_providers()]
    assert names == ['gemini', 'groq']


def test_chat_json_parses(monkeypatch):
    monkeypatch.setenv('GROQ_API_KEY', 'k1')
    with patch('services.llm.requests.post', return_value=_resp('{"ok": true, "n": 3}')):
        out = llm.chat_json('donne du json')
    assert out == {'ok': True, 'n': 3}
