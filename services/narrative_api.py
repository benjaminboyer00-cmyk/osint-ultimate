"""Réponse JSON sûre pour l'endpoint narratif dossier."""
from flask import jsonify

from services.narrative_report import FALLBACK_NARRATIVE_MD, build_narrative_for_entity, markdown_to_html


def _safe_str(val) -> str | None:
    if val is None:
        return None
    return str(val).encode('utf-8', errors='replace').decode('utf-8')


def narrative_json_response(entity_id: int, user_id: int, *, style: str, length: str, use_cache: bool):
    """
    Toujours renvoyer (payload dict, status int) — jamais d'exception vers Werkzeug.
    """
    from services.dossier_access import get_dossier_context

    try:
        ctx = get_dossier_context(entity_id, user_id, min_role='reader')
    except Exception as e:
        return {
            'error': f'Accès dossier : {e}',
            'entity_id': entity_id,
            'markdown': FALLBACK_NARRATIVE_MD,
            'html': markdown_to_html(FALLBACK_NARRATIVE_MD),
            'partial': True,
        }, 200

    if not ctx:
        return {'error': 'Dossier non accessible', 'entity_id': entity_id}, 403

    try:
        out = build_narrative_for_entity(
            entity_id, user_id,
            style=style, length=length, cache_on_scan=use_cache,
        )
    except ValueError as e:
        return {'error': str(e), 'entity_id': entity_id}, 404
    except Exception as e:
        md = FALLBACK_NARRATIVE_MD + f'\n\n_Détail : {e}_\n'
        out = {
            'entity_id': entity_id,
            'anchor_scan_id': None,
            'markdown': md,
            'html': markdown_to_html(md),
            'partial': True,
            'groq_error': str(e),
            'cached': False,
            'style': style,
            'length': length,
        }

    payload = {
        'entity_id': int(out.get('entity_id') or entity_id),
        'anchor_scan_id': out.get('anchor_scan_id'),
        'markdown': _safe_str(out.get('markdown')) or FALLBACK_NARRATIVE_MD,
        'html': _safe_str(out.get('html')) or markdown_to_html(FALLBACK_NARRATIVE_MD),
        'style': _safe_str(out.get('style')) or style,
        'length': _safe_str(out.get('length')) or length,
        'cached': bool(out.get('cached')),
        'dossier_title': _safe_str(out.get('dossier_title')),
        'partial': bool(out.get('partial')),
    }
    if out.get('groq_error'):
        payload['groq_error'] = _safe_str(out.get('groq_error'))
    if out.get('error'):
        payload['error'] = _safe_str(out.get('error'))

    try:
        return payload, 200
    except Exception as e:
        return {
            'error': f'Sérialisation : {e}',
            'entity_id': entity_id,
            'markdown': FALLBACK_NARRATIVE_MD,
            'html': markdown_to_html(FALLBACK_NARRATIVE_MD),
            'partial': True,
        }, 200


def flask_narrative_response(entity_id: int, user_id: int, **kwargs):
    payload, status = narrative_json_response(entity_id, user_id, **kwargs)
    try:
        return jsonify(payload), status
    except Exception as e:
        return jsonify({
            'error': f'JSON : {e}',
            'entity_id': entity_id,
            'markdown': FALLBACK_NARRATIVE_MD,
            'partial': True,
        }), 200
