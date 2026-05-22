"""Géolocalisation des entités — IP-API, carte Leaflet (Phase 5 V7)."""
import json
import logging
import re

import requests

from extensions import db
from models import Entity, Scan

logger = logging.getLogger(__name__)

IP_RE = re.compile(
    r'^(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)(?:\.|$)){4}$'
)
GEO_SECTION_KEYS = (
    'Géolocalisation', 'Géolocalisation IP', 'Module: ip',
)


def _valid_coords(lat, lon) -> bool:
    try:
        lat, lon = float(lat), float(lon)
        return -90 <= lat <= 90 and -180 <= lon <= 180
    except (TypeError, ValueError):
        return False


def fetch_ip_geolocation(ip: str) -> dict | None:
    """Géolocalisation via ip-api.com (gratuit, sans clé)."""
    ip = (ip or '').strip()
    if not IP_RE.match(ip):
        return None
    from services.cache import get_cached, set_cached
    cached = get_cached('ip-api', ip)
    if cached:
        return cached
    try:
        r = requests.get(
            f'http://ip-api.com/json/{ip}',
            params={'fields': 'status,message,country,countryCode,regionName,city,lat,lon,isp,org,proxy,hosting,query'},
            timeout=8,
        )
        if r.status_code != 200:
            return None
        data = r.json()
        if data.get('status') != 'success':
            return None
        out = {
            'lat': data.get('lat'),
            'lon': data.get('lon'),
            'label': ', '.join(filter(None, [
                data.get('city'), data.get('regionName'), data.get('country'),
            ])) or data.get('country', ip),
            'isp': data.get('isp'),
            'org': data.get('org'),
            'proxy': data.get('proxy'),
            'hosting': data.get('hosting'),
        }
        if _valid_coords(out['lat'], out['lon']):
            set_cached('ip-api', ip, out, ttl_hours=168)
            return out
    except Exception as e:
        logger.debug('ip-api %s: %s', ip, e)
    return None


def _geo_from_scan_payload(payload: dict) -> dict | None:
    if not isinstance(payload, dict):
        return None
    for key in GEO_SECTION_KEYS:
        block = payload.get(key)
        if not isinstance(block, dict):
            continue
        lat = block.get('Lat') or block.get('lat')
        lon = block.get('Lon') or block.get('lon')
        if _valid_coords(lat, lon):
            label = ', '.join(filter(None, [
                block.get('Ville') or block.get('city'),
                block.get('Région') or block.get('regionName'),
                block.get('Pays') or block.get('country'),
            ]))
            return {
                'lat': float(lat),
                'lon': float(lon),
                'label': label or block.get('IP', ''),
                'source': 'scan',
            }
    return None


def apply_geo_to_entity(entity: Entity, lat: float, lon: float, label: str = '', source: str = 'ip-api') -> bool:
    if not _valid_coords(lat, lon):
        return False
    entity.latitude = float(lat)
    entity.longitude = float(lon)
    entity.geo_label = (label or entity.value)[:255]
    entity.geo_source = source[:50]
    db.session.add(entity)
    return True


def geolocate_entity(entity: Entity, *, force: bool = False) -> dict | None:
    """Résout et persiste les coordonnées d'une entité."""
    if not force and entity.latitude is not None and entity.longitude is not None:
        return {
            'lat': entity.latitude,
            'lon': entity.longitude,
            'label': entity.geo_label or entity.value,
            'source': entity.geo_source or 'stored',
        }
    if entity.entity_type == 'ip' or IP_RE.match(entity.value or ''):
        loc = fetch_ip_geolocation(entity.value)
        if loc:
            apply_geo_to_entity(entity, loc['lat'], loc['lon'], loc.get('label', ''), 'ip-api')
            return loc
    return None


def enrich_geo_from_scan(scan: Scan, result: dict, user_id: int | None):
    """Après corrélation : met à jour les entités IP / géoloc des résultats."""
    if not user_id or not result:
        return
    geo = _geo_from_scan_payload(result)
    if geo:
        ent = Entity.query.filter_by(
            user_id=user_id, entity_type='ip', value=(scan.target or '').strip(),
        ).first()
        if not ent and IP_RE.match(scan.target or ''):
            ent = Entity.query.filter_by(user_id=user_id, value=scan.target.strip()).first()
        if ent:
            apply_geo_to_entity(ent, geo['lat'], geo['lon'], geo.get('label', ''), geo.get('source', 'scan'))
    if scan.module == 'multi' or result.get('_meta', {}).get('multi'):
        for section, content in result.items():
            if section.startswith('_'):
                continue
            g = _geo_from_scan_payload({section: content} if isinstance(content, dict) else {})
            if not g:
                g = _geo_from_scan_payload(content if isinstance(content, dict) else {})
            if not g:
                continue
            ip_val = None
            if isinstance(content, dict):
                ip_val = content.get('IP') or content.get('ip') or scan.target
            if ip_val and IP_RE.match(str(ip_val)):
                ent = Entity.query.filter_by(user_id=user_id, entity_type='ip', value=str(ip_val).strip()).first()
                if ent:
                    apply_geo_to_entity(ent, g['lat'], g['lon'], g.get('label', ''), 'scan')


def build_map_markers(entity_id: int, user_id: int, *, max_markers: int = 80) -> dict:
    """Marqueurs Leaflet pour le sous-graphe d'une entité racine."""
    from services.correlation import build_graph_json

    root = Entity.query.filter_by(id=entity_id, user_id=user_id).first()
    if not root:
        return {'markers': [], 'root_entity_id': None, 'center': None}

    graph = build_graph_json(entity_id, user_id)
    node_ids = [int(n['id']) for n in graph.get('nodes', []) if n.get('id')][:max_markers]
    markers = []

    for nid in node_ids:
        ent = db.session.get(Entity, nid)
        if not ent or ent.user_id != user_id:
            continue
        loc = geolocate_entity(ent)
        if not loc and ent.latitude is not None:
            loc = {
                'lat': ent.latitude,
                'lon': ent.longitude,
                'label': ent.geo_label or ent.value,
                'source': ent.geo_source or 'stored',
            }
        if not loc or not _valid_coords(loc.get('lat'), loc.get('lon')):
            continue
        markers.append({
            'entity_id': ent.id,
            'lat': loc['lat'],
            'lng': loc['lon'],
            'type': ent.entity_type,
            'value': ent.value,
            'label': loc.get('label') or ent.value,
            'source': loc.get('source') or ent.geo_source,
            'is_root': ent.id == entity_id,
        })

    center = None
    if markers:
        center = {
            'lat': sum(m['lat'] for m in markers) / len(markers),
            'lng': sum(m['lng'] for m in markers) / len(markers),
        }
    elif root.latitude is not None:
        center = {'lat': root.latitude, 'lng': root.longitude}
    else:
        center = {'lat': 48.8566, 'lng': 2.3522}

    return {
        'markers': markers,
        'root_entity_id': entity_id,
        'root_value': root.value,
        'center': center,
        'count': len(markers),
    }


def emit_map_update_after_scan(scan, socketio, opts: dict):
    """Pousse les nouveaux marqueurs après un scan (Socket.IO)."""
    if not socketio or not scan or not scan.user_id:
        return
    root_id = opts.get('_root_entity_id') or opts.get('_map_root_entity_id')
    if not root_id:
        return
    try:
        payload = build_map_markers(int(root_id), scan.user_id)
        room = str(opts.get('_graph_pivot_notify') or scan.user_id)
        socketio.emit('map_update', {
            'scan_id': scan.id,
            'root_entity_id': root_id,
            **payload,
        }, room=room)
    except Exception as e:
        logger.warning('map_update: %s', e)
