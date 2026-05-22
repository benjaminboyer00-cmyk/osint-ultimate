"""Moteur de corrélation — entités et liens après chaque scan."""
import re
from extensions import db
from models import Entity, EntityLink, Scan


def _get_or_create_entity(etype: str, value: str, user_id, scan_id: int) -> Entity:
    value = (value or '').strip().lower() if etype != 'phone' else (value or '').strip()
    ent = Entity.query.filter_by(
        user_id=user_id, entity_type=etype, value=value
    ).first()
    if not ent:
        ent = Entity(
            user_id=user_id,
            entity_type=etype,
            value=value,
            source_scan_id=scan_id,
        )
        db.session.add(ent)
        db.session.flush()
    return ent


def _link(src: Entity, tgt: Entity, link_type: str, proof: str, scan_id: int, user_id):
    existing = EntityLink.query.filter_by(
        user_id=user_id,
        source_id=src.id,
        target_id=tgt.id,
        link_type=link_type,
    ).first()
    if not existing:
        db.session.add(EntityLink(
            user_id=user_id,
            source_id=src.id,
            target_id=tgt.id,
            link_type=link_type,
            source_proof=proof[:500],
            scan_id=scan_id,
        ))


def process_scan_correlations(scan_id: int, module: str, target: str, result: dict, user_id: int | None):
    """Extrait entités et liens à partir d'un résultat de scan."""
    if not user_id or not result or result.get('error'):
        return

    target = (target or '').strip()
    root = _get_or_create_entity(
        {'email': 'email', 'phone': 'phone', 'ip': 'ip', 'site': 'domain',
         'sherlock': 'username', 'pseudo': 'username'}.get(module, 'unknown'),
        target,
        user_id,
        scan_id,
    )

    if module == 'email' and '@' in target:
        local = target.split('@')[0]
        domain = target.split('@')[1]
        dom_ent = _get_or_create_entity('domain', domain, user_id, scan_id)
        _link(root, dom_ent, 'APPARTIENT_A', f'MX domain {domain}', scan_id, user_id)
        if re.match(r'^[\w\.\-]{2,32}$', local):
            pseudo_ent = _get_or_create_entity('username', local.lower(), user_id, scan_id)
            _link(root, pseudo_ent, 'PSEUDO_LOCAL', f'Partie locale email: {local}', scan_id, user_id)

    elif module in ('sherlock', 'pseudo'):
        for platform, status in result.items():
            if 'Existe' in str(status) or '✓' in str(status):
                plat = _get_or_create_entity('platform', platform.lower(), user_id, scan_id)
                _link(root, plat, 'TROUVE_SUR', str(status), scan_id, user_id)

    elif module == 'phone':
        e164 = result.get('Format E.164') or target
        if e164:
            norm = _get_or_create_entity('phone', str(e164), user_id, scan_id)
            if norm.id != root.id:
                _link(root, norm, 'NORMALISE', 'E.164', scan_id, user_id)

    elif module == 'ip':
        hostnames = []
        sh = result.get('Shodan', {})
        if isinstance(sh, dict):
            hostnames = sh.get('Hostnames', []) or []
        for h in hostnames[:5]:
            he = _get_or_create_entity('domain', h.lower(), user_id, scan_id)
            _link(root, he, 'HOSTNAME', 'Shodan', scan_id, user_id)

    db.session.commit()


def build_graph_json(entity_id: int, user_id: int) -> dict:
    """Retourne nœuds et arêtes pour Cytoscape / vis-network."""
    ent = Entity.query.filter_by(id=entity_id, user_id=user_id).first()
    if not ent:
        return {'nodes': [], 'edges': []}

    nodes = {}
    edges = []

    def add_node(e: Entity):
        if e.id not in nodes:
            nodes[e.id] = {
                'id': str(e.id),
                'label': f'{e.entity_type}\n{e.value[:40]}',
                'type': e.entity_type,
                'value': e.value,
            }

    def explore(eid: int, depth=0, max_depth=2):
        if depth > max_depth:
            return
        e = db.session.get(Entity, eid)
        if not e or e.user_id != user_id:
            return
        add_node(e)
        links = EntityLink.query.filter(
            ((EntityLink.source_id == eid) | (EntityLink.target_id == eid)),
            EntityLink.user_id == user_id,
        ).all()
        for link in links:
            other_id = link.target_id if link.source_id == eid else link.source_id
            other = db.session.get(Entity, other_id)
            if other:
                add_node(other)
                edge_id = f'{link.source_id}-{link.target_id}-{link.link_type}'
                if edge_id not in {ed['id'] for ed in edges}:
                    edges.append({
                        'id': edge_id,
                        'source': str(link.source_id),
                        'target': str(link.target_id),
                        'label': link.link_type,
                    })
                explore(other_id, depth + 1, max_depth)

    explore(ent.id)
    return {'nodes': list(nodes.values()), 'edges': edges, 'root_id': str(ent.id)}


def build_entity_links_json(entity_id: int, user_id: int) -> dict | None:
    """Expose les relations déduites pour une entité (API / graphe)."""
    ent = Entity.query.filter_by(id=entity_id, user_id=user_id).first()
    if not ent:
        return None

    links_q = EntityLink.query.filter(
        EntityLink.user_id == user_id,
        (EntityLink.source_id == entity_id) | (EntityLink.target_id == entity_id),
    ).order_by(EntityLink.created_at.desc())

    links_out = []
    for link in links_q.all():
        src = db.session.get(Entity, link.source_id)
        tgt = db.session.get(Entity, link.target_id)
        if not src or not tgt:
            continue
        direction = 'outgoing' if link.source_id == entity_id else 'incoming'
        other = tgt if direction == 'outgoing' else src
        links_out.append({
            'id': link.id,
            'type': link.link_type,
            'direction': direction,
            'proof': link.source_proof,
            'scan_id': link.scan_id,
            'created_at': link.created_at.isoformat() if link.created_at else None,
            'source': {
                'id': src.id,
                'entity_type': src.entity_type,
                'value': src.value,
            },
            'target': {
                'id': tgt.id,
                'entity_type': tgt.entity_type,
                'value': tgt.value,
            },
            'related': {
                'id': other.id,
                'entity_type': other.entity_type,
                'value': other.value,
            },
        })

    return {
        'entity': {
            'id': ent.id,
            'entity_type': ent.entity_type,
            'value': ent.value,
            'source_scan_id': ent.source_scan_id,
            'created_at': ent.created_at.isoformat() if ent.created_at else None,
        },
        'links': links_out,
        'count': len(links_out),
    }
