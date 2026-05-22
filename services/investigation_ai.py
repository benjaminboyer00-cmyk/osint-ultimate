"""Enquête guidée par IA."""
import json
import re
from services.groq import chat_completion, fallback_explain
from services.target_detector import detect_target_type


def parse_suggested_actions(text: str) -> list:
    actions = []
    for line in text.split('\n'):
        line = line.strip()
        if line.startswith('→') or line.startswith('-') or re.match(r'^\d+[\.\)]', line):
            clean = re.sub(r'^[\d\.\)\-→\s]+', '', line).strip()
            if len(clean) > 5:
                actions.append(clean)
    return actions[:5]


def investigate_step(user_message: str, context: dict | None = None) -> dict:
    """Réponse IA + actions suggérées pour le chat d'investigation."""
    ctx = context or {}
    target = ctx.get('last_target', '')
    module = ctx.get('last_module', detect_target_type(user_message) if user_message else 'pseudo')

    system = (
        'Tu es un analyste OSINT expert. Réponds en français. '
        'À la fin, liste 2-4 actions concrètes sous le titre "ACTIONS:" une par ligne avec → '
        'Exemples: "→ Rechercher le pseudo X sur Sherlock", "→ Vérifier le domaine sur Hunter.io". '
        'Ne invente pas de données, base-toi sur le contexte fourni.'
    )
    prompt = f"Question utilisateur: {user_message}\nContexte: {json.dumps(ctx, ensure_ascii=False)[:3000]}"

    try:
        reply = chat_completion(prompt, system=system)
        source = 'groq'
    except Exception as e:
        reply = fallback_explain(
            {'type': module, 'target': target},
            ctx.get('last_result', {}),
        ) + f"\n\n(Erreur IA: {e})"
        source = 'fallback'

    parts = reply.split('ACTIONS:')
    content = parts[0].strip()
    actions = parse_suggested_actions(parts[1] if len(parts) > 1 else reply)

    if not actions and target:
        actions = [
            f'→ Lancer un scan {module} sur « {target} »',
            '→ Consulter le graphe de corrélation',
            '→ Exporter un rapport PDF',
        ]

    return {
        'reply': content,
        'actions': actions,
        'suggested_module': detect_target_type(user_message) if '@' in user_message or len(user_message) < 80 else module,
        'source': source,
    }
