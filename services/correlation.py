"""Moteur de corrélation — entités et liens après chaque scan."""
import re
from extensions import db
from models import Entity, EntityLink, Scan


def _normalize_domain_value(value: str) -> str:
    v = (value or '').strip().lower()
    for prefix in ('http://', 'https://', 'www.'):
        if v.startswith(prefix):
            v = v[len(prefix):]
    return v.split('/')[0].split(':')[0]


def _entities_equivalent(a: Entity, b: Entity) -> bool:
    if not a or not b:
        return False
    if a.id == b.id:
        return True
    if a.entity_type == b.entity_type and (a.value or '').lower() == (b.value or '').lower():
        return True
    if a.entity_type in ('domain', 'unknown', 'site') and b.entity_type in ('domain', 'unknown', 'site'):
        return _normalize_domain_value(a.value) == _normalize_domain_value(b.value)
    return False


def _get_or_create_entity(etype: str, value: str, user_id, scan_id: int, module: str | None = None) -> Entity:
    from services.entity_resolve import get_or_create_entity
    return get_or_create_entity(user_id, etype, value, scan_id, module=module)


def _link(src: Entity, tgt: Entity, link_type: str, proof: str, scan_id: int, user_id, module: str = 'unknown'):
    if _entities_equivalent(src, tgt):
        return
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
    if parent and parent.user_id == user_id and not _entities_equivalent(parent, new_ent):
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
    if module in ('site', 'whois', 'wayback', 'subdomains'):
        target = _normalize_domain_value(target)
    etype_map = {
        'email': 'email', 'phone': 'phone', 'ip': 'ip', 'site': 'domain',
        'whois': 'domain', 'wayback': 'domain', 'subdomains': 'domain',
        'sherlock': 'username', 'pseudo': 'username', 'dorking': 'unknown',
    }
    root = _get_or_create_entity(
        etype_map.get(module, 'unknown'),
        target,
        user_id,
        scan_id,
        module=module,
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
        de = _get_or_create_entity('domain', _normalize_domain_value(target), user_id, scan_id)
        if not _entities_equivalent(root, de):
            _link(root, de, 'DOMAINE', module, scan_id, user_id)

    elif module == 'subdomains':
        for sub in (result.get('Liste') or [])[:80]:
            if not isinstance(sub, str):
                continue
            sd = _get_or_create_entity('domain', _normalize_domain_value(sub), user_id, scan_id)
            if not _entities_equivalent(root, sd):
                _link(root, sd, 'SOUS_DOMAINE', 'crt.sh', scan_id, user_id)

    elif module == 'dorking':
        type_map = {
            'email': 'email', 'username': 'username', 'platform': 'platform',
            'domain': 'domain', 'url': 'platform', 'document': 'platform',
        }
        from services.dorking_filter import is_relevant_entity
        for item in (result.get('Entités') or []):
            if not isinstance(item, dict):
                continue
            etype = type_map.get(item.get('type', ''), 'platform')
            val = (item.get('value') or item.get('url') or '').strip()
            if not val or len(val) > 500:
                continue
            tt = root.entity_type
            if tt == 'unknown':
                tt = 'email' if '@' in target else (
                    'domain' if '.' in target and ' ' not in target else 'username'
                )
            if not is_relevant_entity(
                val, etype, target, tt,
                confidence=float(item.get('confidence') or 0.5),
            ):
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
    from services.dossier_access import get_dossier_context
    ctx = get_dossier_context(entity_id, user_id, min_role='reader')
    if ctx:
        user_id = ctx['owner_user_id']
        ent = ctx['entity']
    else:
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


def build_graph_json(entity_id: int, user_id: int, max_depth: int = 2) -> dict:
    """Retourne nœuds et arêtes pour Cytoscape / vis-network.

    Chargement en masse (2 requêtes) + BFS avec visited set. L'ancienne
    version faisait une requête par nœud et par lien : sur Supabase (base
    distante) chaque requête = un aller-retour réseau, d'où la lenteur.
    """
    from services.dossier_access import get_dossier_context
    ctx = get_dossier_context(entity_id, user_id, min_role='reader')
    if ctx:
        user_id = ctx['owner_user_id']
        ent = ctx['entity']
    else:
        ent = Entity.query.filter_by(id=entity_id, user_id=user_id).first()
    if not ent:
        return {'nodes': [], 'edges': []}

    # 1 requête : tous les liens de l'utilisateur → table d'adjacence en mémoire
    all_links = EntityLink.query.filter(EntityLink.user_id == user_id).all()
    adjacency: dict[int, list] = {}
    for link in all_links:
        adjacency.setdefault(link.source_id, []).append(link)
        adjacency.setdefault(link.target_id, []).append(link)

    # BFS borné à max_depth avec visited set (évite les re-visites)
    visited = {ent.id}
    frontier = [ent.id]
    for _ in range(max(0, max_depth)):
        nxt = []
        for eid in frontier:
            for link in adjacency.get(eid, ()):
                other_id = link.target_id if link.source_id == eid else link.source_id
                if other_id not in visited:
                    visited.add(other_id)
                    nxt.append(other_id)
        if not nxt:
            break
        frontier = nxt

    # 1 requête : toutes les entités du sous-graphe (filtrées sur l'utilisateur)
    ent_rows = Entity.query.filter(
        Entity.id.in_(visited), Entity.user_id == user_id,
    ).all()
    node_ids = {e.id for e in ent_rows}
    nodes = {
        e.id: {
            'id': str(e.id),
            'label': f'{e.entity_type}\n{e.value[:40]}',
            'type': e.entity_type,
            'value': e.value,
        }
        for e in ent_rows
    }

    # Arêtes : tout lien dont les deux extrémités sont dans le sous-graphe
    edges = []
    seen_edges = set()
    for link in all_links:
        if link.source_id not in node_ids or link.target_id not in node_ids:
            continue
        edge_id = f'{link.source_id}-{link.target_id}-{link.link_type}'
        if edge_id in seen_edges:
            continue
        seen_edges.add(edge_id)
        conf = link.confidence if link.confidence is not None else 0.5
        edges.append({
            'id': edge_id,
            'source': str(link.source_id),
            'target': str(link.target_id),
            'label': link.link_type,
            'confidence': conf,
            'width': max(1, int(conf * 6)),
        })

    return {'nodes': list(nodes.values()), 'edges': edges, 'root_id': str(ent.id)}


def build_entity_links_json(entity_id: int, user_id: int) -> dict | None:
    """Expose les relations déduites pour une entité (API / graphe)."""
    from services.dossier_access import get_dossier_context
    ctx = get_dossier_context(entity_id, user_id, min_role='reader')
    if ctx:
        user_id = ctx['owner_user_id']
        ent = ctx['entity']
    else:
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
        if _entities_equivalent(src, tgt):
            continue
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
