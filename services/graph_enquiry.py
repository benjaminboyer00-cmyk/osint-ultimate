"""Mode enquête proactive — suggestion du prochain nœud à analyser."""
from extensions import db
from models import Entity, EntityLink


def suggest_next_node(entity_id: int, user_id: int) -> dict | None:
    """
    Score d'intérêt = (1 - confidence) * connexions * facteur type.
    Retourne le nœud le plus prometteur à investiguer.
    """
    ent = db.session.query(Entity).filter_by(id=entity_id, user_id=user_id).first()
    if not ent:
        return None

    links = db.session.query(EntityLink).filter(
        EntityLink.user_id == user_id,
        (EntityLink.source_id == entity_id) | (EntityLink.target_id == entity_id),
    ).all()

    type_weight = {
        'email': 1.2,
        'username': 1.1,
        'domain': 1.0,
        'phone': 1.0,
        'platform': 0.7,
        'ip': 0.85,
        'unknown': 0.5,
    }

    candidates = {}
    for link in links:
        other_id = link.target_id if link.source_id == entity_id else link.source_id
        other = db.session.get(Entity, other_id)
        if not other:
            continue
        conf = link.confidence if link.confidence is not None else 0.5
        out_degree = db.session.query(EntityLink).filter(
            EntityLink.user_id == user_id,
            EntityLink.source_id == other_id,
        ).count()
        tw = type_weight.get(other.entity_type, 0.6)
        interest = (1.0 - conf) * (1 + out_degree * 0.15) * tw
        if other_id not in candidates or interest > candidates[other_id]['score']:
            candidates[other_id] = {
                'entity_id': other_id,
                'score': interest,
                'entity_type': other.entity_type,
                'value': other.value,
                'confidence': conf,
                'link_type': link.link_type,
            }

    if not candidates:
        return None

    best = max(candidates.values(), key=lambda x: x['score'])
    module_map = {
        'email': 'email', 'phone': 'phone', 'username': 'sherlock',
        'domain': 'whois', 'platform': 'sherlock', 'ip': 'ip',
    }
    mod = module_map.get(best['entity_type'], 'sherlock')
    pct = int((best['confidence'] or 0.5) * 100)
    return {
        'node_id': str(best['entity_id']),
        'entity_id': best['entity_id'],
        'module': mod,
        'target': best['value'],
        'reason': (
            f"Entité prioritaire : {best['entity_type']} « {best['value'][:50]} » "
            f"(confiance {pct}%, lien {best['link_type']})"
        ),
        'confidence': best['confidence'],
        'score': round(best['score'], 3),
    }
