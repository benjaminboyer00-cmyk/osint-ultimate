"""Construction du contexte rapport professionnel (phase 7 — preuve & conformité)."""
import json
from datetime import datetime

from services.report_signing import build_report_hashes
from services.report_pdf import prepare_report_data

# Mapping section → source externe
SOURCE_LABELS = {
    'Shodan': ('Shodan.io', 'API publique'),
    'WHOIS': ('WHOIS / RDAP', 'Registres domaines'),
    'Hunter': ('Hunter.io', 'API email professionnel'),
    'Dehashed': ('Dehashed', 'Fuites agrégées'),
    'Fuites (HIBP)': ('Have I Been Pwned', 'API fuites'),
    'MX': ('DNS', 'Résolution publique'),
    'Géolocalisation': ('Géolocalisation IP', 'Bases publiques'),
    'Historique Web (Wayback)': ('Internet Archive', 'CDX API'),
    'Module: sherlock': ('Sherlock', 'Sites publics'),
    'Module: hunter': ('Hunter.io', 'API'),
    'Module: dehashed': ('Dehashed', 'API'),
    'Module: email': ('Analyse email', 'DNS / SMTP / HIBP'),
    'Module: site': ('Analyse web', 'HTTP / DNS / WHOIS'),
    'Module: whois': ('WHOIS', 'Registre'),
    'Module: wayback': ('Wayback Machine', 'Archive.org'),
    'Module: ip': ('Analyse IP', 'Shodan / géoloc'),
}


def _label_for_section(section: str) -> tuple[str, str]:
    if section in SOURCE_LABELS:
        return SOURCE_LABELS[section]
    if section.startswith('Module:'):
        mod = section.replace('Module:', '').strip()
        return (mod.title(), 'Connecteur OSINT Ultimate')
    return (section, 'Source publique')


def build_traceability(scan, raw_data: dict) -> list[dict]:
    """Chaîne de traçabilité : chaque section = une découverte horodatée."""
    chain = []
    collected_at = scan.completed_at or scan.timestamp or datetime.utcnow()
    ts = collected_at.strftime('%d/%m/%Y %H:%M UTC')

    chain.append({
        'horodatage': ts,
        'source': 'OSINT Ultimate',
        'type': 'Collecte',
        'detail': f"Scan #{scan.id} — module {scan.module} — cible {scan.target}",
    })

    for section, content in (raw_data or {}).items():
        if section.startswith('_'):
            continue
        source_name, source_type = _label_for_section(section)
        detail = _summarize_section(content)
        cached = ''
        if isinstance(content, dict) and content.get('_cached'):
            cached = ' (cache)'
        chain.append({
            'horodatage': ts,
            'source': source_name + cached,
            'type': source_type,
            'detail': f"{section} — {detail}",
        })

    meta = raw_data.get('_meta') or {}
    if meta.get('timeouts'):
        chain.append({
            'horodatage': ts,
            'source': 'Système',
            'type': 'Avertissement',
            'detail': f"Timeouts : {', '.join(meta['timeouts'])}",
        })
    return chain


def _summarize_section(content) -> str:
    if isinstance(content, dict):
        if content.get('Erreur') or content.get('error'):
            return str(content.get('Erreur') or content.get('error'))[:120]
        if content.get('_timeout'):
            return 'Service non disponible (timeout)'
        keys = [k for k in content.keys() if not str(k).startswith('_')][:4]
        return ', '.join(f"{k}" for k in keys) or 'données structurées'
    if isinstance(content, list):
        return f"{len(content)} élément(s)"
    return str(content)[:100]


def build_executive_summary(scan, raw_data: dict, ai_summary: str | None) -> str:
    if ai_summary:
        return ai_summary[:2000]
    lines = [
        f"Investigation OSINT sur la cible « {scan.target} » via le module {scan.module}.",
    ]
    meta = raw_data.get('_meta') or {}
    if meta.get('multi'):
        lines.append(f"Analyse multi-modules : {', '.join(meta.get('modules', []))}.")
    sections = [k for k in raw_data if not k.startswith('_')]
    lines.append(f"{len(sections)} source(s) de données documentée(s) dans ce rapport.")
    return ' '.join(lines)


def build_report_context(
    scan,
    raw_data: dict,
    *,
    investigator: str = '',
    classification: str = 'CONFIDENTIEL',
    graph_image: str | None = None,
    generated_at: str | None = None,
    narrative_html: str | None = None,
    narrative_markdown: str | None = None,
) -> dict:
    """Contexte Jinja unifié pour report.html et report_pro.html."""
    generated_at = generated_at or datetime.utcnow().strftime('%d/%m/%Y %H:%M UTC')
    display_data = prepare_report_data(raw_data)
    hashes = build_report_hashes(scan, raw_data, generated_at)
    traceability = build_traceability(scan, raw_data)

    return {
        'scan': scan,
        'data': display_data,
        'raw_sections': [k for k in raw_data if not k.startswith('_')],
        'ai_summary': scan.ai_summary,
        'graph_image': graph_image,
        'generated_at': generated_at,
        'investigator': investigator or 'Utilisateur OSINT Ultimate',
        'classification': classification,
        'content_hash': hashes['content_hash'],
        'signature_hash': hashes['signature_hash'],
        'report_hash': hashes['content_hash_short'],
        'integrity_json': hashes['integrity_json'],
        'executive_summary': build_executive_summary(scan, raw_data, scan.ai_summary),
        'narrative_content': narrative_html or '',
        'narrative_markdown': narrative_markdown or '',
        'has_narrative': bool(narrative_html),
        'traceability': traceability,
        'methodology': {
            'platform': 'OSINT Ultimate V5',
            'module': scan.module,
            'mode': scan.mode or 'expert',
            'sources_count': len(traceability) - 1,
            'stealth': 'non documenté',
        },
        'app_version': '5.1',
    }


def render_report_html(scan, raw_data: dict, **kwargs) -> str:
    """Génère le HTML du rapport pro."""
    from flask import render_template
    ctx = build_report_context(scan, raw_data, **kwargs)
    return render_template('report_pro.html', **ctx)
