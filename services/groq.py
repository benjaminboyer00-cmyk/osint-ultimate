"""Client API Groq (format OpenAI-compatible)."""
import json
import os
import requests

GROQ_API_BASE = 'https://api.groq.com/openai/v1'
GROQ_DEFAULT_MODEL = 'llama-3.3-70b-versatile'


def _groq_request(messages: list, api_key: str | None = None) -> str:
    """Appel unique POST vers Groq. Lève une exception en cas d'échec."""
    key = api_key or os.environ.get('GROQ_API_KEY')
    if not key:
        raise ValueError('GROQ_API_KEY non configurée dans les secrets du Space')

    model = os.environ.get('GROQ_MODEL', GROQ_DEFAULT_MODEL).strip() or GROQ_DEFAULT_MODEL
    r = requests.post(
        f'{GROQ_API_BASE}/chat/completions',
        headers={
            'Authorization': f'Bearer {key}',
            'Content-Type': 'application/json',
        },
        json={
            'model': model,
            'messages': messages,
        },
        timeout=45,
    )
    if r.status_code != 200:
        err = r.text[:200] if r.text else f'HTTP {r.status_code}'
        raise RuntimeError(f'Erreur API Groq: {err}')

    data = r.json()
    choices = data.get('choices') or []
    if not choices or not choices[0].get('message', {}).get('content'):
        raise RuntimeError('Réponse Groq vide')
    return choices[0]['message']['content'].strip()


def chat_completion(prompt: str, api_key: str | None = None, system: str | None = None) -> str:
    """Complétion chat pour Express / enquête IA."""
    messages = []
    if system:
        messages.append({'role': 'system', 'content': system})
    messages.append({'role': 'user', 'content': str(prompt)[:6000]})
    return _groq_request(messages, api_key)


NARRATIVE_STYLES = {
    'executive': (
        'Style exécutif : phrases courtes, conclusions en tête, vocabulaire accessible '
        'pour un décideur non technique.'
    ),
    'technical': (
        'Style technique : précision des IOC, modules, preuves et limites méthodologiques.'
    ),
    'legal': (
        'Style juridique / conformité : neutralité, sources, chaîne de preuve, '
        'réserves sur l\'usage des données personnelles (RGPD).'
    ),
}

NARRATIVE_LENGTHS = {
    'short': 'Longueur : environ 400 à 600 mots.',
    'medium': 'Longueur : environ 800 à 1200 mots.',
    'long': 'Longueur : environ 1500 à 2000 mots.',
}


def generate_narrative_report(
    data: dict,
    *,
    style: str = 'executive',
    length: str = 'medium',
    api_key: str | None = None,
) -> str:
    """
    Rapport d'enquête en Markdown à partir du JSON dossier (Groq).
    """
    style_hint = NARRATIVE_STYLES.get(style, NARRATIVE_STYLES['executive'])
    length_hint = NARRATIVE_LENGTHS.get(length, NARRATIVE_LENGTHS['medium'])
    payload = json.dumps(data, ensure_ascii=False, default=str)[:14000]

    system = (
        'Tu es un analyste en renseignement cyber et investigations numériques. '
        'Tu rédiges en français un rapport d\'enquête professionnel à partir de données OSINT structurées. '
        'Réponds UNIQUEMENT en Markdown (titres ##, listes, tableaux si utile). '
        'Structure obligatoire :\n'
        '## Introduction\n'
        '## Méthodologie\n'
        '## Chronologie des faits\n'
        '## Corrélations et relations clés\n'
        '## Analyse et hypothèses\n'
        '## Recommandations\n'
        '## Conclusion\n'
        f'{style_hint} {length_hint} '
        'Ne invente pas de faits absents des données ; signale les lacunes.'
    )
    user = (
        'Voici le dossier d\'investigation (entités, liens, scans, sources). '
        'Rédige le rapport narratif complet :\n\n'
        f'{payload}'
    )
    messages = [
        {'role': 'system', 'content': system},
        {'role': 'user', 'content': user},
    ]
    try:
        return _groq_request(messages, api_key)
    except ValueError as e:
        return f'## Rapport narratif\n\n_Rapport IA indisponible : {e}_'
    except RuntimeError as e:
        return f'## Rapport narratif\n\n_Erreur Groq : {e}_'


def markdown_to_html(md: str) -> str:
    """Convertit le Markdown narratif en HTML pour WeasyPrint."""
    if not md:
        return ''
    try:
        import markdown2
        return markdown2.markdown(
            md,
            extras=['fenced-code-blocks', 'tables', 'header-ids', 'strike'],
        )
    except ImportError:
        import html
        return f'<pre>{html.escape(md)}</pre>'


def fallback_explain(card: dict, result: dict) -> str:
    """Explication locale si Groq indisponible."""
    lines = [
        '📋 **Résumé automatique** (mode hors-ligne — API Groq indisponible)',
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
        lines.append("**Points d'attention :**")
        for r in card['risks']:
            lines.append(f'⚠️ {r}')
    if card.get('next_steps'):
        lines.append('')
        lines.append('**Prochaines étapes suggérées :**')
        for s in card['next_steps']:
            lines.append(f'→ {s}')
    lines.append('')
    lines.append('_Configurez GROQ_API_KEY dans les secrets Hugging Face._')
    return '\n'.join(lines)
