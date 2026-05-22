"""Orchestration rapport narratif IA (Phase 3 V7)."""
from extensions import db
from models import Scan
from services.groq import generate_narrative_report, markdown_to_html
from services.report_data import build_report_data, merge_scan_payloads, pick_anchor_scan


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
        if stored.startswith('## Introduction') or stored.startswith('## Méthodologie'):
            markdown = stored
            cached = True

    if not markdown:
        markdown = generate_narrative_report(data, style=style, length=length)
        if (
            cache_on_scan and anchor and markdown
            and '## Introduction' in markdown
        ):
            anchor.ai_summary = markdown
            db.session.commit()

    return {
        'entity_id': entity_id,
        'anchor_scan_id': anchor.id if anchor else None,
        'markdown': markdown,
        'html': markdown_to_html(markdown),
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

    nar = build_narrative_for_entity(
        entity_id, user_id,
        style=kwargs.pop('style', 'executive'),
        length=kwargs.pop('length', 'medium'),
        cache_on_scan=kwargs.pop('use_cache', True),
    )
    raw = merge_scan_payloads(entity_id, user_id)
    if not raw or len(raw) <= 1:
        import json
        raw = json.loads(anchor.result_json or '{}')

    return anchor, raw, nar['html'], nar['markdown']
