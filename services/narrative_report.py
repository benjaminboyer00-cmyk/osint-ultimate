"""Orchestration rapport narratif IA (Phase 3 V7)."""
import logging

from extensions import db
from models import Scan
from services.groq import generate_narrative_report, markdown_to_html
from services.report_data import build_report_data, merge_scan_payloads, pick_anchor_scan
from services.report_consolidate import extract_technical_facts

logger = logging.getLogger(__name__)

def _narrative_cache_is_stale(text: str) -> bool:
    """Ignore l'ancien format (raconte les scans / surveillance)."""
    if not text or len(text) < 80:
        return True
    low = text.lower()
    stale_markers = (
        'surveillance', 'scan répété', 'scans répétés', 'méthodologie',
        'chronologie des faits', '## introduction',
        'investigation elle-même', 'processus d\'investigation',
    )
    return any(m in low for m in stale_markers)


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
    Ne lève jamais d'exception technique (fallback Groq / données).
    """
    try:
        return _build_narrative_for_entity_impl(
            entity_id, user_id,
            style=style, length=length, cache_on_scan=cache_on_scan,
        )
    except ValueError:
        raise
    except Exception as e:
        logger.exception('narrative entity=%s user=%s', entity_id, user_id)
        md = FALLBACK_NARRATIVE_MD + f'\n\n_Détail : {e}_\n'
        return {
            'entity_id': entity_id,
            'anchor_scan_id': None,
            'markdown': md,
            'html': markdown_to_html(md),
            'style': style,
            'length': length,
            'cached': False,
            'dossier_title': None,
            'groq_error': str(e),
            'partial': True,
        }


def _build_narrative_for_entity_impl(
    entity_id: int,
    user_id: int,
    *,
    style: str = 'executive',
    length: str = 'medium',
    cache_on_scan: bool = True,
) -> dict:
    import os
    data = build_report_data(entity_id, user_id)
    if not data:
        raise ValueError('Dossier non trouvé ou données indisponibles')

    anchor = pick_anchor_scan(entity_id, user_id)
    markdown = None
    cached = False
    groq_note = None

    if cache_on_scan and anchor and getattr(anchor, 'ai_summary', None):
        stored = (anchor.ai_summary or '').strip()
        if (
            stored.startswith('## Synthèse exécutive')
            or stored.startswith('## Profil de la cible')
        ) and not _narrative_cache_is_stale(stored):
            markdown = stored
            cached = True

    if not markdown:
        if not os.environ.get('GROQ_API_KEY'):
            groq_note = 'GROQ_API_KEY non configurée sur le serveur'
            markdown = FALLBACK_NARRATIVE_MD + f'\n\n_{groq_note}_\n'
        else:
            try:
                root_val = (data.get('dossier') or {}).get('root_entity') or {}
                try:
                    consolidated = merge_scan_payloads(entity_id, user_id)
                except Exception as ex:
                    logger.warning('merge_scan_payloads entity=%s: %s', entity_id, ex)
                    consolidated = {}
                facts = extract_technical_facts(consolidated, root_val.get('value', ''))
                markdown = generate_narrative_report(
                    data, style=style, length=length, technical_facts=facts,
                )
            except Exception as e:
                logger.error('Groq narrative entity=%s: %s', entity_id, e)
                markdown = FALLBACK_NARRATIVE_MD + f'\n\n_Détail technique : {e}_\n'
                groq_note = str(e)
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

    html = markdown_to_html(markdown or FALLBACK_NARRATIVE_MD)

    anchor_id = None
    if anchor is not None:
        try:
            anchor_id = int(anchor.id)
        except Exception:
            anchor_id = None

    out = {
        'entity_id': entity_id,
        'anchor_scan_id': anchor_id,
        'markdown': markdown or FALLBACK_NARRATIVE_MD,
        'html': html,
        'style': style,
        'length': length,
        'cached': cached,
        'dossier_title': (data.get('dossier') or {}).get('title'),
    }
    if groq_note:
        out['groq_error'] = groq_note
    return out


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
