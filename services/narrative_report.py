"""Orchestration rapport narratif IA (Phase 3 V7)."""
import logging

from extensions import db
from models import Scan
from services.groq import generate_narrative_report, markdown_to_html
from services.report_data import build_report_data, merge_scan_payloads, pick_anchor_scan
from services.report_consolidate import extract_technical_facts

logger = logging.getLogger(__name__)

FALLBACK_NARRATIVE_MD = (
    '## Rapport narratif\n\n'
    '*La génération automatique (Groq) est temporairement indisponible. '
    'Le reste du rapport (données, traçabilité, empreintes) est inclus ci-dessous.*\n'
)


def build_narrative_for_entity(
    entity_id: int,
    user_id: int,
    *,
    style: str = 'executive',
    length: str = 'medium',
    cache_on_scan: bool = True,
) -> dict:
    """
    Génère le rapport narratif Markdown + HTML.
    Retourne {markdown, html, entity_id, anchor_scan_id, cached}.
    """
    data = build_report_data(entity_id, user_id)
    if not data:
        raise ValueError('Dossier non trouvé')

    anchor = pick_anchor_scan(entity_id, user_id)
    markdown = None
    cached = False

    if cache_on_scan and anchor and getattr(anchor, 'ai_summary', None):
        stored = (anchor.ai_summary or '').strip()
        if stored.startswith('## ') and any(
            stored.startswith(h) for h in (
                '## Introduction', '## Méthodologie', '## Synthèse exécutive', '## Profil',
            )
        ):
            markdown = stored
            cached = True

    if not markdown:
        try:
            root_val = (data.get('dossier') or {}).get('root_entity') or {}
            consolidated = merge_scan_payloads(entity_id, user_id)
            facts = extract_technical_facts(consolidated, root_val.get('value', ''))
            markdown = generate_narrative_report(
                data, style=style, length=length, technical_facts=facts,
            )
        except Exception as e:
            logger.error('Groq narrative entity=%s: %s', entity_id, e)
            markdown = FALLBACK_NARRATIVE_MD + f'\n\n_Détail technique : {e}_\n'
        if (
            cache_on_scan and anchor and markdown
            and '## Introduction' in markdown
            and 'indisponible' not in markdown.lower()
        ):
            try:
                anchor.ai_summary = markdown
                db.session.commit()
            except Exception:
                db.session.rollback()

    html = ''
    try:
        html = markdown_to_html(markdown or FALLBACK_NARRATIVE_MD)
    except Exception as e:
        logger.warning('markdown_to_html: %s', e)
        html = f'<p>{markdown or FALLBACK_NARRATIVE_MD}</p>'

    return {
        'entity_id': entity_id,
        'anchor_scan_id': anchor.id if anchor else None,
        'markdown': markdown or FALLBACK_NARRATIVE_MD,
        'html': html,
        'style': style,
        'length': length,
        'cached': cached,
        'dossier_title': data['dossier'].get('title'),
    }


def narrative_pdf_context(entity_id: int, user_id: int, **kwargs) -> tuple:
    """
    Prépare (scan, raw_data, narrative_html, narrative_markdown) pour export PDF.
    """
    anchor = pick_anchor_scan(entity_id, user_id)
    if not anchor:
        raise ValueError('Aucun scan terminé pour ce dossier — lancez au moins une analyse')

    nar_html = ''
    nar_md = FALLBACK_NARRATIVE_MD
    try:
        nar = build_narrative_for_entity(
            entity_id, user_id,
            style=kwargs.pop('style', 'executive'),
            length=kwargs.pop('length', 'medium'),
            cache_on_scan=kwargs.pop('use_cache', True),
        )
        nar_html = nar.get('html') or ''
        nar_md = nar.get('markdown') or FALLBACK_NARRATIVE_MD
    except Exception as e:
        logger.error('narrative_pdf_context entity=%s: %s', entity_id, e)
        try:
            nar_html = markdown_to_html(FALLBACK_NARRATIVE_MD)
        except Exception:
            nar_html = '<p>Rapport narratif indisponible.</p>'

    try:
        raw = merge_scan_payloads(entity_id, user_id)
    except Exception as e:
        logger.warning('merge_scan_payloads: %s', e)
        raw = {}
    if not raw or len(raw) <= 1:
        import json
        try:
            raw = json.loads(anchor.result_json or '{}')
        except Exception:
            raw = {'_note_pdf': 'Données source limitées'}

    return anchor, raw, nar_html, nar_md
