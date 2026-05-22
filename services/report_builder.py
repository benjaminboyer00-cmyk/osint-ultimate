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


def _section_status(content) -> str:
    """Statut collecte pour l'annexe de traçabilité."""
    if isinstance(content, dict):
        if content.get('_not_executed'):
            return 'non exécuté'
        if content.get('Statut') == 'Indisponible' or content.get('_timeout'):
            return 'timeout'
        if content.get('Erreur') or content.get('error') or content.get('Statut') == 'Échec de collecte':
            return 'erreur'
        if content.get('_degraded') or content.get('_source') == 'scraping_fallback':
            return 'fallback'
        if content.get('_cached'):
            return 'cache'
    if isinstance(content, str) and 'non configur' in content.lower():
        return 'non exécuté'
    return 'succès'


def build_traceability(scan, raw_data: dict) -> list[dict]:
    """Chaîne de traçabilité : une ligne par source consolidée (pas par scan dupliqué)."""
    chain = []
    collected_at = scan.completed_at or scan.timestamp or datetime.utcnow()
    ts = collected_at.strftime('%d/%m/%Y %H:%M UTC')
    meta = raw_data.get('_meta') or {}

    chain.append({
        'horodatage': ts,
        'source': 'OSINT Ultimate',
        'type': 'Rapport consolidé',
        'statut': 'succès',
        'detail': (
            f"Dossier — {meta.get('scan_count', 1)} scan(s) agrégé(s) — "
            f"modules : {', '.join(meta.get('modules_executed', [scan.module]))}"
        ),
    })

    whois_logged = False
    for section, content in (raw_data or {}).items():
        if section.startswith('_'):
            continue
        if section == 'WHOIS' and whois_logged:
            continue
        source_name, source_type = _label_for_section(section)
        detail = _summarize_section(content)
        statut = _section_status(content)
        if isinstance(content, dict) and content.get('_not_executed'):
            statut = 'non exécuté'
            detail = content.get('Raison', 'Module non exécuté')
        if section == 'WHOIS' and statut in ('erreur', 'timeout'):
            whois_logged = True
            if meta.get('whois_notice'):
                detail = meta['whois_notice'][:200]
        scan_ref = ''
        if isinstance(content, dict) and content.get('_dernier_scan'):
            scan_ref = f" ({content['_dernier_scan']})"
        chain.append({
            'horodatage': ts,
            'source': source_name,
            'type': source_type,
            'statut': statut,
            'detail': f"{section}{scan_ref} — {detail}",
        })

    if meta.get('timeouts'):
        chain.append({
            'horodatage': ts,
            'source': 'Système',
            'type': 'Avertissement',
            'statut': 'timeout',
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
    base_url: str | None = None,
) -> dict:
    """Contexte Jinja unifié pour report.html et report_pro.html."""
    generated_at = generated_at or datetime.utcnow().strftime('%d/%m/%Y %H:%M UTC')
    display_data = prepare_report_data(raw_data)
    hashes = build_report_hashes(scan, raw_data, generated_at)
    traceability = build_traceability(scan, raw_data)
    from services.report_seal import build_seal_assets
    seal = build_seal_assets(scan.id, base_url)
    stored_pdf_hash = getattr(scan, 'report_pdf_hash', None) or ''

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
        'verify_url': seal['verify_url'],
        'qr_data_uri': seal['qr_data_uri'],
        'stored_pdf_hash': stored_pdf_hash,
        'has_stored_pdf_hash': bool(stored_pdf_hash),
        'traceability': traceability,
        'scan_history': (raw_data.get('_meta') or {}).get('scan_history', []),
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
