"""Couche LLM multi-fournisseur (tiers gratuits prioritaires) avec cache.

Essaie les fournisseurs configurés dans l'ordre jusqu'à réussite. Tous
exposent une API compatible OpenAI (``/chat/completions``), d'où un code
d'appel unique. Un cache TTL en mémoire évite de re-dépenser des tokens
sur des requêtes identiques.

Ordre par défaut (chacun a un tier gratuit) :
  1. groq       — très rapide, ``GROQ_API_KEY``
  2. gemini     — Flash, ~1500 req/j gratuit, ``GEMINI_API_KEY`` (endpoint OpenAI-compat)
  3. cerebras   — rapide, ``CEREBRAS_API_KEY``
  4. openrouter — modèles ``:free``, ``OPENROUTER_API_KEY`` (filet de secours)

Configurable via ``LLM_PROVIDER_ORDER`` (ex. ``gemini,groq``) et
``LLM_CACHE_TTL`` (secondes). Rétro-compatible : avec seulement
``GROQ_API_KEY``, le comportement est identique à l'ancien client Groq.
"""
import hashlib
import json
import logging
import os

import requests
from cachetools import TTLCache

logger = logging.getLogger(__name__)

_CACHE = TTLCache(maxsize=512, ttl=int(os.environ.get('LLM_CACHE_TTL', '900') or '900'))

PROVIDERS = [
    {
        'name': 'groq',
        'base': 'https://api.groq.com/openai/v1',
        'key_env': 'GROQ_API_KEY',
        'model_env': 'GROQ_MODEL',
        'default_model': 'llama-3.3-70b-versatile',
        'fast_env': 'GROQ_FAST_MODEL',
        'default_fast': 'llama-3.1-8b-instant',
    },
    {
        'name': 'gemini',
        'base': 'https://generativelanguage.googleapis.com/v1beta/openai',
        'key_env': 'GEMINI_API_KEY',
        'model_env': 'GEMINI_MODEL',
        'default_model': 'gemini-2.0-flash',
        'fast_env': 'GEMINI_FAST_MODEL',
        'default_fast': 'gemini-2.0-flash-lite',
    },
    {
        'name': 'cerebras',
        'base': 'https://api.cerebras.ai/v1',
        'key_env': 'CEREBRAS_API_KEY',
        'model_env': 'CEREBRAS_MODEL',
        'default_model': 'llama-3.3-70b',
        'fast_env': 'CEREBRAS_FAST_MODEL',
        'default_fast': 'llama3.1-8b',
    },
    {
        'name': 'openrouter',
        'base': 'https://openrouter.ai/api/v1',
        'key_env': 'OPENROUTER_API_KEY',
        'model_env': 'OPENROUTER_MODEL',
        'default_model': 'meta-llama/llama-3.3-70b-instruct:free',
        'fast_env': 'OPENROUTER_FAST_MODEL',
        'default_fast': 'meta-llama/llama-3.1-8b-instruct:free',
    },
]

_BY_NAME = {p['name']: p for p in PROVIDERS}


def _configured_providers() -> list[dict]:
    """Fournisseurs disposant d'une clé, dans l'ordre voulu."""
    order_env = os.environ.get('LLM_PROVIDER_ORDER', '').strip()
    provs = PROVIDERS
    if order_env:
        wanted = [p.strip().lower() for p in order_env.split(',') if p.strip()]
        provs = [_BY_NAME[w] for w in wanted if w in _BY_NAME]
    return [p for p in provs if os.environ.get(p['key_env'])]


def _cache_key(messages: list, json_mode: bool, fast: bool, max_tokens) -> str:
    raw = json.dumps(messages, ensure_ascii=False, sort_keys=True, default=str)
    return hashlib.sha256(f'{raw}|{json_mode}|{fast}|{max_tokens}'.encode('utf-8')).hexdigest()


def _one_call(provider: dict, messages: list, json_mode: bool, timeout: int,
              fast: bool, max_tokens) -> str:
    key = os.environ.get(provider['key_env'])
    if fast:
        model = (os.environ.get(provider.get('fast_env', '')) or '').strip() or provider.get('default_fast') or provider['default_model']
    else:
        model = (os.environ.get(provider['model_env']) or '').strip() or provider['default_model']
    payload = {'model': model, 'messages': messages}
    if json_mode:
        payload['response_format'] = {'type': 'json_object'}
    if max_tokens:
        payload['max_tokens'] = int(max_tokens)
    r = requests.post(
        f"{provider['base']}/chat/completions",
        headers={
            'Authorization': f'Bearer {key}',
            'Content-Type': 'application/json',
        },
        json=payload,
        timeout=timeout,
    )
    if r.status_code != 200:
        raise RuntimeError(f"{provider['name']} HTTP {r.status_code}: {(r.text or '')[:160]}")
    data = r.json()
    choices = data.get('choices') or []
    content = choices[0].get('message', {}).get('content') if choices else None
    if not content:
        raise RuntimeError(f"{provider['name']} : réponse vide")
    return content.strip()


def llm_chat(
    messages: list,
    *,
    json_mode: bool = False,
    timeout: int = int(os.environ.get('LLM_TIMEOUT', '20')),
    use_cache: bool = True,
    fast: bool = False,
    max_tokens: int | None = None,
) -> str:
    """Complétion chat robuste avec bascule multi-fournisseur.

    ``fast`` : utilise un modèle 8B rapide (planification/chat/résumés).
    ``max_tokens`` : plafonne la génération -> latence réduite.
    Lève ``ValueError`` si aucun fournisseur, ``RuntimeError`` si tous échouent.
    """
    providers = _configured_providers()
    if not providers:
        raise ValueError(
            'Aucun fournisseur LLM configuré '
            '(GROQ_API_KEY, GEMINI_API_KEY, CEREBRAS_API_KEY, OPENROUTER_API_KEY)'
        )
    ck = _cache_key(messages, json_mode, fast, max_tokens) if use_cache else None
    if ck and ck in _CACHE:
        return _CACHE[ck]

    errors = []
    for p in providers:
        try:
            out = _one_call(p, messages, json_mode, timeout, fast, max_tokens)
            if ck:
                _CACHE[ck] = out
            return out
        except Exception as e:  # noqa: BLE001 — on tente le fournisseur suivant
            logger.warning('LLM provider %s a échoué: %s', p['name'], e)
            errors.append(f"{p['name']}: {e}")
            continue
    raise RuntimeError('Tous les fournisseurs LLM ont échoué — ' + ' | '.join(errors[:4]))


def chat(prompt: str, *, system: str | None = None, json_mode: bool = False,
         fast: bool = False, max_tokens: int | None = None) -> str:
    """Raccourci prompt/système."""
    messages = []
    if system:
        messages.append({'role': 'system', 'content': system})
    messages.append({'role': 'user', 'content': str(prompt)[:12000]})
    return llm_chat(messages, json_mode=json_mode, fast=fast, max_tokens=max_tokens)


def chat_json(prompt: str, *, system: str | None = None,
              fast: bool = False, max_tokens: int | None = None) -> dict | list | None:
    """Complétion attendue en JSON. Retourne None si le parsing échoue."""
    raw = chat(prompt, system=system, json_mode=True, fast=fast, max_tokens=max_tokens)
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        import re
        m = re.search(r'[\{\[][\s\S]*[\}\]]', raw or '')
        if m:
            try:
                return json.loads(m.group(0))
            except json.JSONDecodeError:
                return None
        return None


def provider_status() -> dict:
    """Diagnostic : fournisseurs configurés / disponibles + taille du cache."""
    return {
        'configured': [p['name'] for p in _configured_providers()],
        'available': [p['name'] for p in PROVIDERS],
        'cache_size': len(_CACHE),
    }
