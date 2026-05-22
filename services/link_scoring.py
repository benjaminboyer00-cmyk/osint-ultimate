"""Scoring de confiance pour les liens du graphe."""
import json
from datetime import datetime

from extensions import db

# Confiance de base par module source (0.0 – 1.0)
MODULE_CONFIDENCE = {
    'email': 0.90,
    'phone': 0.85,
    'whois': 0.88,
    'hunter': 0.82,
    'dehashed': 0.80,
    'epieos': 0.78,
    'sherlock': 0.70,
    'pseudo': 0.68,
    'github': 0.75,
    'ip': 0.85,
    'shodan': 0.83,
    'site': 0.72,
    'wayback': 0.65,
    'messaging': 0.55,
    'multi': 0.60,
}

LINK_TYPE_BOOST = {
    'APPARTIENT_A': 0.05,
    'EMAIL_PRO': 0.08,
    'FUITES': 0.06,
    'TROUVE_SUR': 0.0,
    'PSEUDO_LOCAL': 0.04,
    'ENRICHIT': 0.03,
}


def base_confidence(module: str, link_type: str = '') -> float:
    m = (module or 'unknown').lower().replace('module: ', '').strip()
    base = MODULE_CONFIDENCE.get(m, 0.55)
    boost = LINK_TYPE_BOOST.get(link_type, 0.0)
    return min(0.98, base + boost)


def merge_sources(existing_json: str | None, module: str) -> list:
    sources = []
    if existing_json:
        try:
            sources = json.loads(existing_json)
        except Exception:
            sources = []
    if module and module not in sources:
        sources.append(module)
    return sources[:10]


def compute_confidence(sources: list, link_type: str = '') -> float:
    """Plusieurs sources corroborantes augmentent le score."""
    if not sources:
        return 0.5
    scores = [base_confidence(s, link_type) for s in sources]
    avg = sum(scores) / len(scores)
    corroboration = min(0.15, (len(sources) - 1) * 0.05)
    return min(0.98, avg + corroboration)


def upsert_link_scored(link, module: str, link_type: str):
    """Met à jour confidence et sources sur un EntityLink existant ou nouveau."""
    sources = merge_sources(link.sources_json, module)
    link.sources_json = json.dumps(sources, ensure_ascii=False)
    link.confidence = compute_confidence(sources, link_type)
    link.updated_at = datetime.utcnow()
