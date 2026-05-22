"""Résolution entité ↔ cible pour graphe et monitoring."""
from models import Entity
from services.target_detector import detect_target_type, target_category


def _entity_type_for_target(target: str, module: str | None = None) -> str:
    cat = target_category(target)
    if module in ('sherlock', 'pseudo', 'github'):
        return 'username'
    mapping = {
        'email': 'email',
        'phone': 'phone',
        'ip': 'ip',
        'domain': 'domain',
        'site': 'domain',
        'pseudo': 'username',
    }
    return mapping.get(cat, 'unknown')


def _normalize_value(entity_type: str, target: str) -> str:
    t = (target or '').strip()
    if entity_type == 'email':
        return t.lower()
    if entity_type == 'phone':
        return t
    if entity_type == 'domain':
        return t.lower().replace('http://', '').replace('https://', '').split('/')[0].replace('www.', '')
    if entity_type == 'username':
        return t.lower().lstrip('@')
    return t.lower()


def find_entity_for_target(user_id: int, target: str, module: str | None = None) -> Entity | None:
    """Trouve l'entité la plus pertinente pour une cible surveillée."""
    if not user_id or not target:
        return None
    etype = _entity_type_for_target(target, module)
    val = _normalize_value(etype, target)
    ent = Entity.query.filter_by(
        user_id=user_id, entity_type=etype, value=val,
    ).first()
    if ent:
        return ent
    if '@' in target:
        local = target.split('@')[0].lower()
        ent = Entity.query.filter_by(
            user_id=user_id, entity_type='username', value=local,
        ).first()
        if ent:
            return ent
        ent = Entity.query.filter_by(
            user_id=user_id, entity_type='email', value=target.lower(),
        ).first()
        if ent:
            return ent
    return Entity.query.filter(
        Entity.user_id == user_id,
        Entity.value.ilike(f'%{val[:40]}%'),
    ).order_by(Entity.created_at.desc()).first()
