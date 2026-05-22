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


def _link(src: Entity, tgt: Entity, link_type: str, proof: str, scan_id: int, user_id, module: str = 'unknown'):
    from services.link_scoring import upsert_link_scored
    existing = EntityLink.query.filter_by(
        user_id=user_id,
        source_id=src.id,
        target_id=tgt.id,
        link_type=link_type,
    ).first()
    mod = module
    if '—' in proof:
        mod = proof.split('—')[0].strip().lower() or module
    if not existing:
        row = EntityLink(
            user_id=user_id,
            source_id=src.id,
            target_id=tgt.id,
            link_type=link_type,
            source_proof=proof[:500],
            scan_id=scan_id,
        )
        upsert_link_scored(row, mod, link_type)
        db.session.add(row)
    else:
        upsert_link_scored(existing, mod, link_type)


def _link_to_root(root_entity_id: int | None, new_ent: Entity, scan_id: int, user_id: int, proof: str):
    if not root_entity_id or not new_ent:
        return
    parent = db.session.get(Entity, root_entity_id)
    if parent and parent.user_id == user_id and parent.id != new_ent.id:
        _link(parent, new_ent, 'ENRICHIT', proof[:500], scan_id, user_id)


def process_scan_correlations(
    scan_id: int, module: str, target: str, result: dict, user_id: int | None,
    root_entity_id: int | None = None,
):
    """Extrait entités et liens à partir d'un résultat de scan."""
    if not user_id or not result or result.get('error'):
        return
    if isinstance(result, dict) and result.get('_timeout'):
        return

    target = (target or '').strip()
    root = _get_or_create_entity(
        {'email': 'email', 'phone': 'phone', 'ip': 'ip', 'site': 'domain',
         'sherlock': 'username', 'pseudo': 'username', 'dorking': 'unknown'}.get(module, 'unknown'),
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

    elif module == 'hunter':
        for row in (result.get('Liste') or []):
            if isinstance(row, dict) and row.get('Email'):
                em = _get_or_create_entity('email', row['Email'].lower(), user_id, scan_id)
                _link(root, em, 'EMAIL_PRO', f"Hunter — {row.get('Poste', '')}", scan_id, user_id)

    elif module == 'dehashed':
        for row in (result.get('Entrées') or []):
            if isinstance(row, dict):
                if row.get('Email'):
                    em = _get_or_create_entity('email', row['Email'].lower(), user_id, scan_id)
                    _link(root, em, 'FUITES', row.get('Base', ''), scan_id, user_id)
                if row.get('Username'):
                    un = _get_or_create_entity('username', row['Username'].lower(), user_id, scan_id)
                    _link(root, un, 'FUITES_PSEUDO', row.get('Base', ''), scan_id, user_id)

    elif module in ('whois', 'site', 'wayback'):
        dom = target
        if '@' not in dom:
            dom = dom.replace('http://', '').replace('https://', '').split('/')[0]
            de = _get_or_create_entity('domain', dom.lower(), user_id, scan_id)
            if de.id != root.id:
                _link(root, de, 'DOMAINE', module, scan_id, user_id)

    elif module == 'dorking':
        type_map = {
            'email': 'email', 'username': 'username', 'platform': 'platform',
            'domain': 'domain', 'url': 'platform', 'document': 'platform',
        }
        for item in (result.get('Entités') or []):
            if not isinstance(item, dict):
                continue
            etype = type_map.get(item.get('type', ''), 'platform')
            val = (item.get('value') or item.get('url') or '').strip()
            if not val or len(val) > 500:
                continue
            child = _get_or_create_entity(etype, val.lower() if etype != 'phone' else val, user_id, scan_id)
            proof = (item.get('snippet') or item.get('platform') or 'dorking')[:200]
            _link(root, child, 'DORKING', proof, scan_id, user_id, module='dorking')

    # Rebond email → pseudo local (déduction)
    if module == 'email' and '@' in target:
        local = target.split('@')[0]
        if re.match(r'^[\w\.\-]{2,32}$', local):
            _link(
                root,
                _get_or_create_entity('username', local.lower(), user_id, scan_id),
                'REBOND_SHERLOCK',
                'Suggestion: lancer scan sherlock sur ce pseudo',
                scan_id,
                user_id,
            )

    _link_to_root(root_entity_id, root, scan_id, user_id, f'Scan {module} depuis graphe')
    db.session.commit()


def process_multi_correlations(
    scan_id: int, target: str, result: dict, user_id: int | None,
    root_entity_id: int | None = None,
):
    """Corrélation pour chaque section d'un scan multi-modules."""
    if not user_id or not isinstance(result, dict):
        return
    for key, section in result.items():
        if key.startswith('_') or not key.startswith('Module:'):
            continue
        mod = key.replace('Module:', '').strip()
        if isinstance(section, dict) and not section.get('_timeout'):
            process_scan_correlations(
                scan_id, mod, target, section, user_id, root_entity_id=root_entity_id,
            )
    # Historique wayback
    wb = result.get('Historique Web (Wayback)')
    if isinstance(wb, dict):
        process_scan_correlations(
            scan_id, 'wayback', target, wb, user_id, root_entity_id=root_entity_id,
        )


def get_rebound_suggestions(entity_id: int, user_id: int) -> list:
    """Actions de corrélation suggérées pour une entité."""
    ent = Entity.query.filter_by(id=entity_id, user_id=user_id).first()
    if not ent:
        return []
    suggestions = []
    if ent.entity_type == 'email' and '@' in ent.value:
        local = ent.value.split('@')[0]
        suggestions.append({'module': 'sherlock', 'target': local, 'reason': 'Pseudo déduit de l\'email'})
        suggestions.append({'module': 'dehashed', 'target': ent.value, 'reason': 'Fuites associées'})
        suggestions.append({'module': 'epieos', 'target': ent.value, 'reason': 'Enrichissement Epieos'})
    elif ent.entity_type == 'username':
        suggestions.append({'module': 'sherlock', 'target': ent.value, 'reason': 'Recherche multi-plateformes'})
    elif ent.entity_type == 'domain':
        suggestions.append({'module': 'hunter', 'target': ent.value, 'reason': 'Emails professionnels'})
        suggestions.append({'module': 'wayback', 'target': ent.value, 'reason': 'Historique web'})
        suggestions.append({'module': 'whois', 'target': ent.value, 'reason': 'WHOIS'})
    elif ent.entity_type == 'phone':
        suggestions.append({'module': 'messaging', 'target': ent.value, 'reason': 'Messageries'})
        suggestions.append({'module': 'phone', 'target': ent.value, 'reason': 'Analyse téléphone'})
    return suggestions


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
                    conf = link.confidence if link.confidence is not None else 0.5
                    edges.append({
                        'id': edge_id,
                        'source': str(link.source_id),
                        'target': str(link.target_id),
                        'label': link.link_type,
                        'confidence': conf,
                        'width': max(1, int(conf * 6)),
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
