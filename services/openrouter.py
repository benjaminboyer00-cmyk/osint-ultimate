"""Client OpenRouter robuste — multi-modèles, repli local."""
import json
import os
import requests

# Modèles gratuits testés sur OpenRouter (ordre de priorité)
DEFAULT_MODELS = [
    'google/gemma-2-9b-it:free',
    'meta-llama/llama-3.2-3b-instruct:free',
    'qwen/qwen-2.5-7b-instruct:free',
    'microsoft/phi-3-mini-128k-instruct:free',
    'openchat/openchat-7b:free',
    'mistralai/mistral-7b-instruct:free',
]


def _models_list():
    forced = os.environ.get('OPENROUTER_MODEL', '').strip()
    if forced:
        return [forced] + [m for m in DEFAULT_MODELS if m != forced]
    return DEFAULT_MODELS


def _headers(api_key: str) -> dict:
    return {
        'Authorization': f'Bearer {api_key}',
        'Content-Type': 'application/json',
        'HTTP-Referer': os.environ.get(
            'OPENROUTER_REFERER',
            'https://huggingface.co/spaces/benji4565/osint_ultimate_backend',
        ),
        'X-Title': 'OSINT Ultimate',
    }


def _extract_error(response) -> str:
    try:
        body = response.json()
        err = body.get('error', {})
        if isinstance(err, dict):
            return err.get('message') or err.get('code') or str(err)
        return str(err) or f'HTTP {response.status_code}'
    except Exception:
        return f'HTTP {response.status_code}: {(response.text or "")[:200]}'


def chat_completion(prompt: str, api_key: str | None = None, system: str | None = None) -> str:
    """
    Appelle OpenRouter avec essai sur plusieurs modèles.
    Lève RuntimeError si tous échouent.
    """
    key = api_key or os.environ.get('OPENROUTER_KEY') or os.environ.get('ANTHROPIC_API_KEY')
    if not key:
        raise ValueError('OPENROUTER_KEY non configurée dans les secrets du Space')

    messages = []
    if system:
        messages.append({'role': 'system', 'content': system})
    messages.append({'role': 'user', 'content': str(prompt)[:6000]})

    payload_base = {
        'messages': messages,
        'max_tokens': int(os.environ.get('OPENROUTER_MAX_TOKENS', '1024')),
        'temperature': float(os.environ.get('OPENROUTER_TEMPERATURE', '0.4')),
    }

    errors = []
    for model in _models_list():
        try:
            r = requests.post(
                'https://openrouter.ai/api/v1/chat/completions',
                headers=_headers(key),
                json={**payload_base, 'model': model},
                timeout=45,
            )
            if r.status_code == 200:
                data = r.json()
                choices = data.get('choices') or []
                if choices and choices[0].get('message', {}).get('content'):
                    return choices[0]['message']['content'].strip()
                errors.append(f'{model}: réponse vide')
                continue
            msg = _extract_error(r)
            errors.append(f'{model}: {msg}')
            # Continuer sur erreur provider / 404 / 429
        except requests.Timeout:
            errors.append(f'{model}: timeout')
        except Exception as e:
            errors.append(f'{model}: {e}')

    raise RuntimeError(
        'Tous les modèles OpenRouter ont échoué. '
        + (' | '.join(errors[-3:]) if errors else 'vérifiez OPENROUTER_KEY')
    )


def fallback_explain(card: dict, result: dict) -> str:
    """Explication locale sans IA si OpenRouter indisponible."""
    lines = [
        '📋 **Résumé automatique** (mode hors-ligne — OpenRouter indisponible)',
        '',
        f"**Type d'analyse :** {card.get('type', 'OSINT')}",
        f"**Cible :** {card.get('target', '—')}",
        '',
    ]
    if card.get('highlights'):
        lines.append('**Points clés :**')
        for h in card['highlights'][:8]:
            lines.append(f"• {h.get('label', '?')} : {h.get('value', '—')}")
    if card.get('risks'):
        lines.append('')
        lines.append('**Points d\'attention :**')
        for r in card['risks']:
            lines.append(f"⚠️ {r}")
    if card.get('next_steps'):
        lines.append('')
        lines.append('**Prochaines étapes suggérées :**')
        for s in card['next_steps']:
            lines.append(f"→ {s}")
    lines.append('')
    lines.append('_Configurez OPENROUTER_KEY ou essayez OPENROUTER_MODEL dans les secrets HF._')
    return '\n'.join(lines)
