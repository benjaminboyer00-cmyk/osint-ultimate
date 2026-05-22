"""Résolution entité ↔ cible pour graphe, corrélation et monitoring."""
from extensions import db
from models import Entity
from services.target_detector import detect_target_type, target_category


def _normalize_domain_value(value: str) -> str:
    v = (value or '').strip().lower()
    for prefix in ('http://', 'https://', 'www.'):
        if v.startswith(prefix):
            v = v[len(prefix):]
    return v.split('/')[0].split(':')[0]


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
    if entity_type == 'domain':
        return _normalize_domain_value(t)
    if entity_type == 'email':
        return t.lower()
    if entity_type == 'phone':
        return t
    if entity_type == 'username':
        return t.lower().lstrip('@')
    return t.lower()


def find_entity_by_type_value(user_id: int, entity_type: str, value: str) -> Entity | None:
    """Recherche exacte (type + valeur normalisée), avec équivalence domaine/unknown."""
    if not user_id or not value:
        return None
    etype = (entity_type or 'unknown').lower()
    val = _normalize_value(etype, value)
    ent = db.session.query(Entity).filter_by(
        user_id=user_id, entity_type=etype, value=val,
    ).first()
    if ent:
        return ent
    if etype in ('domain', 'unknown', 'site'):
        for alt_type in ('domain', 'unknown', 'site'):
            if alt_type == etype:
                continue
            ent = db.session.query(Entity).filter_by(
                user_id=user_id, entity_type=alt_type, value=val,
            ).first()
            if ent:
                return ent
    return None


def get_or_create_entity(
    user_id: int,
    entity_type: str,
    value: str,
    scan_id: int | None = None,
    *,
    module: str | None = None,
) -> Entity:
    """
    Crée une entité uniquement si aucune correspondance n'existe déjà
    (recherche exacte puis find_entity_for_target).
    """
    etype = (entity_type or 'unknown').lower()
    existing = find_entity_by_type_value(user_id, etype, value)
    if existing:
        return existing

    mod = module or {
        'email': 'email', 'phone': 'phone', 'username': 'sherlock',
        'domain': 'site', 'ip': 'ip',
    }.get(etype)
    fuzzy = find_entity_for_target(user_id, value, mod)
    if fuzzy:
        if fuzzy.entity_type == etype:
            return fuzzy
        if etype in ('domain', 'unknown', 'site') and fuzzy.entity_type in ('domain', 'unknown', 'site'):
            return fuzzy
        if etype == 'username' and fuzzy.entity_type == 'email' and '@' in (fuzzy.value or ''):
            if fuzzy.value.split('@')[0].lower() == _normalize_value('username', value):
                return fuzzy

    val = _normalize_value(etype, value)
    ent = Entity(
        user_id=user_id,
        entity_type=etype,
        value=val,
        source_scan_id=scan_id,
    )
    db.session.add(ent)
    db.session.flush()
    return ent


def find_entity_for_target(user_id: int, target: str, module: str | None = None) -> Entity | None:
    """Trouve l'entité la plus pertinente pour une cible surveillée."""
    if not user_id or not target:
        return None
    etype = _entity_type_for_target(target, module)
    val = _normalize_value(etype, target)
    ent = db.session.query(Entity).filter_by(
        user_id=user_id, entity_type=etype, value=val,
    ).first()
    if ent:
        return ent
    if '@' in target:
        local = target.split('@')[0].lower()
        ent = db.session.query(Entity).filter_by(
            user_id=user_id, entity_type='username', value=local,
        ).first()
        if ent:
            return ent
        ent = db.session.query(Entity).filter_by(
            user_id=user_id, entity_type='email', value=target.lower(),
        ).first()
        if ent:
            return ent
    return db.session.query(Entity).filter(
        Entity.user_id == user_id,
        Entity.value.ilike(f'%{val[:40]}%'),
    ).order_by(Entity.created_at.desc()).first()
