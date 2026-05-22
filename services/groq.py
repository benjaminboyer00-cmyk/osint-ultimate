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


def _format_technical_facts(facts: dict | None) -> str:
    if not facts:
        return ''
    lines = ['## Faits établis (données techniques — à utiliser comme base du rapport)']
    lines.append(f"**Cible :** {facts.get('cible', '—')}")
    for section, key in (
        ('Infrastructure & domaine', 'infrastructure'),
        ('Réseau & hébergement', 'reseau'),
        ('Identité & enregistrement', 'identite'),
        ('Sécurité & certificats', 'securite'),
        ('Lacunes documentées', 'lacunes'),
    ):
        items = facts.get(key) or []
        if items:
            lines.append(f'\n### {section}')
            for item in items:
                lines.append(f'- {item}')
    return '\n'.join(lines)


def generate_narrative_report(
    data: dict,
    *,
    style: str = 'executive',
    length: str = 'medium',
    api_key: str | None = None,
    technical_facts: dict | None = None,
) -> str:
    """
    Rapport d'enquête en Markdown — décrit la CIBLE, pas les scans internes.
    """
    style_hint = NARRATIVE_STYLES.get(style, NARRATIVE_STYLES['executive'])
    length_hint = NARRATIVE_LENGTHS.get(length, NARRATIVE_LENGTHS['medium'])
    facts_block = _format_technical_facts(technical_facts)
    slim = {
        'cible': (data.get('dossier') or {}).get('root_entity'),
        'entites_cles': (data.get('entities') or [])[:25],
        'liens': (data.get('links') or [])[:20],
        'sources_documentees': (data.get('sources') or [])[:15],
    }
    payload = json.dumps(slim, ensure_ascii=False, default=str)[:8000]

    system = (
        'Tu es un analyste OSINT senior. Tu rédiges en français un rapport professionnel '
        'sur la CIBLE de l\'investigation (domaine, personne, infrastructure), '
        'à destination d\'un RSSI, d\'un service juridique ou d\'un décideur.\n\n'
        'RÈGLES STRICTES :\n'
        '- Décris UNIQUEMENT la cible : infrastructure, hébergement, DNS, WHOIS, certificats, '
        'exposition, risques techniques.\n'
        '- NE JAMAIS parler des scans, de la surveillance, des modules, ni du processus '
        'd\'investigation interne.\n'
        '- NE PAS suggérer que l\'enquête est suspecte ou répétitive.\n'
        '- Appuie-toi sur le bloc « Faits établis » ; ne invente pas de données absentes.\n'
        '- Mentionne explicitement les lacunes listées (ex. WHOIS indisponible) sans dramatiser.\n'
        '- Réponds UNIQUEMENT en Markdown (titres ##, listes).\n\n'
        'Structure obligatoire :\n'
        '## Synthèse exécutive\n'
        '## Profil de la cible\n'
        '## Infrastructure et hébergement\n'
        '## Identité numérique et enregistrements\n'
        '## Sécurité et exposition\n'
        '## Risques et recommandations\n'
        '## Conclusion\n'
        f'{style_hint} {length_hint}'
    )
    user = (
        f'{facts_block}\n\n'
        'Contexte complémentaire (entités et liens, sans détail des scans) :\n'
        f'{payload}\n\n'
        'Rédige le rapport en te comportant comme un analyste décrivant ce que '
        'révèle l\'infrastructure de la cible (ex. hébergement AWS, MX OVH, certificat Let\'s Encrypt…).'
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
    import html as html_module
    text = str(md).encode('utf-8', errors='replace').decode('utf-8')
    try:
        import markdown2
        return markdown2.markdown(
            text,
            extras=['fenced-code-blocks', 'tables'],
        )
    except ImportError:
        return f'<pre>{html_module.escape(text)}</pre>'
    except Exception:
        return f'<pre>{html_module.escape(text)}</pre>'


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
