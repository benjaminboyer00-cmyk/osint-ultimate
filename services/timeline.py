"""Frise chronologique d'investigation — format vis-timeline (Phase 6 V7)."""
import json
import logging
import re
from datetime import datetime

from extensions import db
from models import Entity, EntityLink, Scan

logger = logging.getLogger(__name__)

GROUPS = [
    {'id': 1, 'content': '🔍 Scans'},
    {'id': 2, 'content': '🌐 Domaines / WHOIS'},
    {'id': 3, 'content': '🕰️ Wayback'},
    {'id': 4, 'content': '🔓 Fuites de données'},
    {'id': 5, 'content': '👤 Entités découvertes'},
    {'id': 6, 'content': '🔗 Corrélations'},
]

_WB_DATE = re.compile(r'^(\d{4})(\d{2})(\d{2})')


def _parse_date(value) -> str | None:
    """Retourne une date ISO (YYYY-MM-DD ou ISO complet) pour vis-timeline."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    s = str(value).strip()
    if not s or s.upper() in ('N/A', 'NONE', '—', '-'):
        return None
    m = _WB_DATE.match(s[:8])
    if m:
        return f'{m.group(1)}-{m.group(2)}-{m.group(3)}'
    if s.endswith('Z'):
        s = s[:-1] + '+00:00'
    for fmt in (
        '%Y-%m-%dT%H:%M:%S%z',
        '%Y-%m-%dT%H:%M:%S',
        '%Y-%m-%d %H:%M:%S',
        '%Y-%m-%d',
        '%d/%m/%Y',
        '%d-%m-%Y',
    ):
        try:
            dt = datetime.strptime(s[:26].replace('+00:00', ''), fmt.replace('%z', ''))
            return dt.isoformat()
        except ValueError:
            continue
    return None


def _related_scans(user_id: int, root_value: str, entity_ids: set[int]) -> list[Scan]:
    root_l = (root_value or '').lower()
    out = []
    for s in Scan.query.filter_by(user_id=user_id).order_by(Scan.timestamp.desc()).limit(120).all():
        if s.status != 'completed':
            continue
        hit = s.target.lower() == root_l or root_l in (s.result_json or '').lower()
        if not hit:
            for eid in entity_ids:
                ent = db.session.get(Entity, eid)
                if ent and ent.value.lower() in (s.target.lower(), (s.result_json or '').lower()):
                    hit = True
                    break
        if hit:
            out.append(s)
    return out


def _collect_dated_events(scan_id: int, payload: dict, _id: list) -> list[dict]:
    """Extrait événements datés d'un bloc JSON de résultat."""
    events = []
    if not isinstance(payload, dict):
        return events

    for whois_key in ('WHOIS', 'Domaine WHOIS', 'Module: whois'):
        block = payload.get(whois_key)
        if not isinstance(block, dict):
            continue
        for label, field in (('Création domaine', 'Création'), ('Expiration', 'Expiration')):
            dt = _parse_date(block.get(field))
            if dt:
                _id[0] += 1
                events.append({
                    'id': _id[0],
                    'group': 2,
                    'content': label,
                    'start': dt,
                    'title': f'{block.get("Registrar", "")} — scan #{scan_id}',
                    'scan_id': scan_id,
                    'event_kind': 'whois',
                    'className': 'evt-whois',
                })

    for wb_key in ('Historique Web (Wayback)', 'Module: wayback'):
        wb = payload.get(wb_key)
        if not isinstance(wb, dict):
            continue
        snaps = wb.get('Snapshots')
        if not isinstance(snaps, list):
            continue
        for snap in snaps[:25]:
            if not isinstance(snap, dict):
                continue
            dt = _parse_date(snap.get('Date'))
            if not dt:
                continue
            _id[0] += 1
            events.append({
                'id': _id[0],
                'group': 3,
                'content': 'Snapshot Wayback',
                'start': dt,
                'title': (snap.get('URL') or '')[:120],
                'scan_id': scan_id,
                'event_kind': 'wayback',
                'className': 'evt-wayback',
                'archive': snap.get('Lien archive'),
            })

    for leak_key in ('Module: dehashed', 'Dehashed'):
        block = payload.get(leak_key)
        if not isinstance(block, dict):
            continue
        for row in (block.get('Entrées') or []):
            if not isinstance(row, dict):
                continue
            dt = _parse_date(row.get('Date'))
            base = row.get('Base') or row.get('database_name') or 'Fuite'
            if not dt:
                continue
            _id[0] += 1
            events.append({
                'id': _id[0],
                'group': 4,
                'content': f'Fuite — {base}'[:80],
                'start': dt,
                'title': row.get('Email') or row.get('Username') or base,
                'scan_id': scan_id,
                'event_kind': 'breach',
                'className': 'evt-breach',
            })

    if isinstance(payload.get('Fuites (HIBP)'), list):
        for name in payload['Fuites (HIBP)'][:15]:
            if not isinstance(name, str):
                continue
            _id[0] += 1
            events.append({
                'id': _id[0],
                'group': 4,
                'content': f'HIBP — {name}'[:80],
                'start': None,
                'title': str(name),
                'scan_id': scan_id,
                'event_kind': 'hibp',
                'className': 'evt-breach',
            })

    return events


def _events_from_scan_payload(scan_id: int, payload: dict, _id: list) -> list[dict]:
    """Extrait événements datés des sections d'un résultat (simple ou multi)."""
    if not isinstance(payload, dict):
        return []
    events = _collect_dated_events(scan_id, payload, _id)
    for key, section in payload.items():
        if key.startswith('Module:') and isinstance(section, dict):
            wrapped = dict(section)
            wrapped[key] = section
            for ev in _collect_dated_events(scan_id, wrapped, _id):
                events.append(ev)
    return events


def build_timeline(entity_id: int, user_id: int, *, max_items: int = 120) -> dict | None:
    """
    JSON compatible vis-timeline : groups, items, meta.
    """
    root = Entity.query.filter_by(id=entity_id, user_id=user_id).first()
    if not root:
        return None

    from services.correlation import build_graph_json
    graph = build_graph_json(entity_id, user_id)
    entity_ids = {int(n['id']) for n in graph.get('nodes', []) if n.get('id')}
    entity_ids.add(entity_id)

    items = []
    seq = [0]

    for s in _related_scans(user_id, root.value, entity_ids):
        start = _parse_date(s.completed_at or s.timestamp)
        if start:
            seq[0] += 1
            items.append({
                'id': seq[0],
                'group': 1,
                'content': f'Scan {s.module}',
                'start': start,
                'title': f'#{s.id} — {s.target}'[:200],
                'scan_id': s.id,
                'event_kind': 'scan',
                'className': 'evt-scan',
            })
        try:
            payload = json.loads(s.result_json or '{}')
        except Exception:
            payload = {}
        items.extend(_events_from_scan_payload(s.id, payload, seq))

    for eid in entity_ids:
        ent = db.session.get(Entity, eid)
        if not ent or ent.user_id != user_id:
            continue
        dt = _parse_date(ent.created_at)
        if dt and ent.id != entity_id:
            seq[0] += 1
            items.append({
                'id': seq[0],
                'group': 5,
                'content': f'{ent.entity_type}',
                'start': dt,
                'title': ent.value[:120],
                'entity_id': ent.id,
                'event_kind': 'entity',
                'className': 'evt-entity',
            })

    links = EntityLink.query.filter(
        EntityLink.user_id == user_id,
        (EntityLink.source_id.in_(entity_ids)) | (EntityLink.target_id.in_(entity_ids)),
    ).order_by(EntityLink.created_at.desc()).limit(80).all()

    for link in links:
        dt = _parse_date(link.created_at)
        if not dt:
            continue
        other_id = link.target_id if link.source_id in entity_ids else link.source_id
        seq[0] += 1
        items.append({
            'id': seq[0],
            'group': 6,
            'content': link.link_type,
            'start': dt,
            'title': (link.source_proof or '')[:120],
            'entity_id': other_id,
            'scan_id': link.scan_id,
            'event_kind': 'link',
            'className': 'evt-link',
        })

    scan_starts = {it['scan_id']: it['start'] for it in items if it.get('event_kind') == 'scan' and it.get('scan_id')}
    for it in items:
        if not it.get('start') and it.get('scan_id') in scan_starts:
            it['start'] = scan_starts[it['scan_id']]
    items = [it for it in items if it.get('start')]

    # Dédupliquer par (group, start, content)
    seen = set()
    unique = []
    for it in items:
        key = (it.get('group'), it.get('start'), it.get('content'))
        if key in seen:
            continue
        seen.add(key)
        unique.append(it)

    unique.sort(key=lambda x: x.get('start', ''))
    unique = unique[-max_items:]

    if root.created_at:
        seq[0] += 1
        unique.insert(0, {
            'id': seq[0],
            'group': 5,
            'content': 'Cible racine',
            'start': _parse_date(root.created_at),
            'title': root.value,
            'entity_id': root.id,
            'event_kind': 'entity',
            'className': 'evt-root',
        })

    return {
        'groups': GROUPS,
        'items': [_vis_item(it) for it in unique],
        'root_entity_id': entity_id,
        'root_value': root.value,
        'count': len(unique),
    }


def _vis_item(it: dict) -> dict:
    """Format compatible vis-timeline (pas de clé ``type`` réservée)."""
    out = {
        'id': it['id'],
        'group': it['group'],
        'content': it.get('content', ''),
        'start': it.get('start'),
        'title': it.get('title', ''),
        'className': it.get('className', ''),
    }
    if it.get('entity_id'):
        out['entity_id'] = it['entity_id']
    if it.get('scan_id'):
        out['scan_id'] = it['scan_id']
    if it.get('archive'):
        out['archive'] = it['archive']
    return out


def emit_timeline_update_after_scan(scan, socketio, opts: dict):
    """Pousse la timeline mise à jour via Socket.IO."""
    if not socketio or not scan or not scan.user_id:
        return
    root_id = opts.get('_root_entity_id')
    if not root_id:
        return
    try:
        payload = build_timeline(int(root_id), scan.user_id)
        if not payload:
            return
        room = str(opts.get('_graph_pivot_notify') or scan.user_id)
        socketio.emit('timeline_update', {
            'scan_id': scan.id,
            'root_entity_id': root_id,
            **payload,
        }, room=room)
    except Exception as e:
        logger.warning('timeline_update: %s', e)
