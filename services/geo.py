"""Géolocalisation des entités — scans, IP-API, carte Leaflet (Phase 5 V7)."""
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
MODULE_ENTITY_TYPE = {
    'phone': 'phone',
    'ip': 'ip',
    'site': 'domain',
    'whois': 'domain',
    'wayback': 'domain',
    'email': 'email',
    'sherlock': 'username',
    'pseudo': 'username',
    'dorking': 'unknown',
}
PAYS_KEYS = ('Pays', 'Country', 'country', 'countryCode', 'Code pays')


def _valid_coords(lat, lon) -> bool:
    try:
        lat, lon = float(lat), float(lon)
        return -90 <= lat <= 90 and -180 <= lon <= 180
    except (TypeError, ValueError):
        return False


def _normalize_domain(value: str) -> str:
    v = (value or '').strip().lower()
    for prefix in ('http://', 'https://', 'www.'):
        if v.startswith(prefix):
            v = v[len(prefix):]
    return v.split('/')[0].split(':')[0]


def _normalize_phone(value: str) -> str:
    return re.sub(r'[\s\-\(\)\.]', '', (value or '').strip())


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
            'precision': 'city' if data.get('city') else 'region',
            'source': 'ip-api',
        }
        if _valid_coords(out['lat'], out['lon']):
            set_cached('ip-api', ip, out, ttl_hours=168)
            return out
    except Exception as e:
        logger.debug('ip-api %s: %s', ip, e)
    return None


def _extract_pays_from_block(block: dict) -> str:
    if not isinstance(block, dict):
        return ''
    for key in PAYS_KEYS:
        v = block.get(key)
        if v and str(v).strip().lower() not in ('n/a', 'na', 'unknown', 'inconnu'):
            return str(v).strip()
    return ''


def _geo_from_block(block: dict, *, default_source: str = 'scan') -> dict | None:
    if not isinstance(block, dict):
        return None
    lat = block.get('Lat') or block.get('lat')
    lon = block.get('Lon') or block.get('lon') or block.get('lng')
    if _valid_coords(lat, lon):
        label = ', '.join(filter(None, [
            block.get('Ville') or block.get('city'),
            block.get('Région') or block.get('regionName'),
            block.get('Pays') or block.get('country'),
        ]))
        prec = block.get('Précision') or block.get('precision') or 'city'
        return {
            'lat': float(lat),
            'lon': float(lon),
            'label': label or block.get('IP', ''),
            'source': default_source,
            'precision': prec,
        }
    pays = _extract_pays_from_block(block)
    if pays:
        from services.country_geo import coords_for_country
        loc = coords_for_country(pays)
        if loc:
            loc['source'] = default_source
            if block.get('Ville') or block.get('city'):
                loc['label'] = ', '.join(filter(None, [
                    block.get('Ville') or block.get('city'), loc['label'],
                ]))
            return loc
    return None


def _geo_from_scan_payload(payload: dict) -> dict | None:
    if not isinstance(payload, dict):
        return None
    for key in GEO_SECTION_KEYS:
        block = payload.get(key)
        g = _geo_from_block(block)
        if g:
            return g
    pays = _extract_pays_from_block(payload)
    if pays:
        from services.country_geo import coords_for_country
        return coords_for_country(pays)
    return None


def collect_geo_placements(result: dict, module: str, target: str) -> list[dict]:
    """
    Liste les positions à appliquer : [{entity_type, value, lat, lon, label, source, precision}, ...]
    """
    if not isinstance(result, dict) or result.get('error'):
        return []
    placements = []
    target = (target or '').strip()
    mod = (module or '').strip().lower()

    def add(etype: str, value: str, geo: dict, source: str):
        if not value or not geo or not _valid_coords(geo.get('lat'), geo.get('lon')):
            return
        placements.append({
            'entity_type': etype,
            'value': value,
            'lat': geo['lat'],
            'lon': geo['lon'],
            'label': geo.get('label') or value,
            'source': geo.get('source') or source,
            'precision': geo.get('precision') or 'unknown',
        })

    primary_type = MODULE_ENTITY_TYPE.get(mod, 'unknown')
    primary_val = target
    if primary_type == 'domain':
        primary_val = _normalize_domain(target)
    elif primary_type == 'phone':
        primary_val = _normalize_phone(target) or target

    geo_main = _geo_from_scan_payload(result)
    if geo_main:
        add(primary_type, primary_val, geo_main, f'{mod}-scan')

    if mod == 'phone':
        pays = result.get('Pays') or ''
        if pays and not geo_main:
            from services.country_geo import coords_for_country
            loc = coords_for_country(str(pays))
            if loc:
                loc['label'] = f'{pays} (indicatif téléphonique)'
                loc['source'] = 'phone-libphonenumber'
                add('phone', primary_val, loc, 'phone-pays')

    if mod in ('site', 'whois', 'wayback'):
        ip_val = result.get('IP')
        if ip_val and IP_RE.match(str(ip_val).strip()):
            g_ip = _geo_from_scan_payload(result)
            if not g_ip:
                g_ip = fetch_ip_geolocation(str(ip_val).strip())
            if g_ip:
                add('ip', str(ip_val).strip(), g_ip, 'site-resolve-ip')

    whois_block = result.get('WHOIS') or result.get('Domaine WHOIS')
    if isinstance(whois_block, dict):
        pays = whois_block.get('Pays')
        if pays and primary_type == 'domain':
            from services.country_geo import coords_for_country
            loc = coords_for_country(str(pays))
            if loc and not any(p['entity_type'] == 'domain' for p in placements):
                loc['label'] = f'WHOIS — {pays}'
                loc['source'] = 'whois-pays'
                add('domain', primary_val, loc, 'whois-pays')

    if mod == 'multi' or result.get('_meta', {}).get('multi'):
        for section, content in result.items():
            if section.startswith('_'):
                continue
            sub_mod = section.replace('Module:', '').strip() if section.startswith('Module:') else None
            if sub_mod:
                placements.extend(collect_geo_placements(content, sub_mod, target))
            elif isinstance(content, dict):
                g = _geo_from_scan_payload(content)
                if g:
                    st = MODULE_ENTITY_TYPE.get(sub_mod or '', primary_type)
                    add(st, primary_val if st == primary_type else target, g, 'multi-section')

    seen = set()
    unique = []
    for p in placements:
        key = (p['entity_type'], p['value'].lower() if p['entity_type'] != 'phone' else p['value'], round(p['lat'], 2), round(p['lon'], 2))
        if key in seen:
            continue
        seen.add(key)
        unique.append(p)
    return unique


def _find_entity(user_id: int, etype: str, value: str) -> Entity | None:
    value = (value or '').strip()
    if not value:
        return None
    if etype == 'phone':
        norm = _normalize_phone(value)
        for cand in {value, norm, value.replace(' ', '')}:
            if not cand:
                continue
            ent = Entity.query.filter_by(
                user_id=user_id, entity_type='phone', value=cand,
            ).first()
            if ent:
                return ent
        ents = Entity.query.filter_by(user_id=user_id, entity_type='phone').limit(200).all()
        for ent in ents:
            if _normalize_phone(ent.value) == norm:
                return ent
        return None
    lookup = value.lower() if etype != 'phone' else value
    if etype == 'domain':
        lookup = _normalize_domain(value)
    return Entity.query.filter_by(
        user_id=user_id, entity_type=etype, value=lookup,
    ).first()


def apply_geo_to_entity(entity: Entity, lat: float, lon: float, label: str = '', source: str = 'ip-api') -> bool:
    if not _valid_coords(lat, lon):
        return False
    entity.latitude = float(lat)
    entity.longitude = float(lon)
    entity.geo_label = (label or entity.value)[:255]
    entity.geo_source = source[:50]
    db.session.add(entity)
    return True


def geolocate_entity(entity: Entity, *, force: bool = False, allow_network: bool = True) -> dict | None:
    """Résout et persiste les coordonnées d'une entité."""
    if not force and entity.latitude is not None and entity.longitude is not None:
        return {
            'lat': entity.latitude,
            'lon': entity.longitude,
            'label': entity.geo_label or entity.value,
            'source': entity.geo_source or 'stored',
            'precision': 'stored',
        }
    if not allow_network:
        return None
    if entity.entity_type == 'ip' or IP_RE.match(entity.value or ''):
        loc = fetch_ip_geolocation(entity.value)
        if loc:
            apply_geo_to_entity(entity, loc['lat'], loc['lon'], loc.get('label', ''), loc.get('source', 'ip-api'))
            return loc
    if entity.entity_type == 'phone':
        from services.country_geo import coords_for_country
        import phonenumbers
        try:
            phone = phonenumbers.parse(entity.value, None)
            region = phonenumbers.region_code_for_number(phone)
            if region:
                loc = coords_for_country(region)
                if loc:
                    loc['label'] = f'{loc["label"]} (téléphone)'
                    apply_geo_to_entity(entity, loc['lat'], loc['lon'], loc['label'], 'phone-region')
                    return loc
        except Exception:
            pass
    if entity.entity_type == 'domain':
        try:
            import socket
            ip = socket.gethostbyname(_normalize_domain(entity.value))
            loc = fetch_ip_geolocation(ip)
            if loc:
                loc['label'] = f'{loc.get("label", "")} — hébergement {entity.value}'
                apply_geo_to_entity(entity, loc['lat'], loc['lon'], loc['label'], 'domain-dns')
                return loc
        except Exception as e:
            logger.debug('domain dns geo %s: %s', entity.value, e)
    return None


def enrich_geo_from_scan(scan: Scan, result: dict, user_id: int | None):
    """Après corrélation : persiste géoloc sur entités (phone, domaine, IP)."""
    if not user_id or not result:
        return
    for placement in collect_geo_placements(result, scan.module or '', scan.target or ''):
        ent = _find_entity(user_id, placement['entity_type'], placement['value'])
        if not ent and placement['entity_type'] == 'ip':
            ent = Entity.query.filter_by(
                user_id=user_id, value=placement['value'],
            ).first()
        if ent:
            apply_geo_to_entity(
                ent,
                placement['lat'],
                placement['lon'],
                placement.get('label', ''),
                placement.get('source', 'scan'),
            )


def hydrate_entities_from_scans(entity_ids: list[int], user_id: int, *, max_scans: int = 120) -> int:
    """
    Rejoue les scans passés pour remplir latitude/longitude sans appel réseau supplémentaire.
    Retourne le nombre d'entités mises à jour.
    """
    if not entity_ids:
        return 0
    entities = []
    for eid in entity_ids:
        ent = db.session.get(Entity, eid)
        if ent and ent.user_id == user_id:
            entities.append(ent)
    if not entities:
        return 0

    values_lower = set()
    for ent in entities:
        values_lower.add(ent.value.lower())
        if ent.entity_type == 'domain':
            values_lower.add(_normalize_domain(ent.value))
        if ent.entity_type == 'phone':
            values_lower.add(_normalize_phone(ent.value))

    scans = (
        Scan.query.filter_by(user_id=user_id)
        .filter(Scan.status == 'completed')
        .order_by(Scan.timestamp.desc())
        .limit(max_scans)
        .all()
    )
    updated = 0
    for ent in entities:
        if ent.latitude is not None and ent.longitude is not None:
            continue
        for scan in scans:
            try:
                payload = json.loads(scan.result_json or '{}')
            except json.JSONDecodeError:
                continue
            tgt_l = (scan.target or '').lower()
            ent_l = ent.value.lower()
            if ent.entity_type == 'domain':
                ent_l = _normalize_domain(ent.value)
            if ent_l not in tgt_l and ent_l not in (scan.result_json or '').lower():
                if ent.entity_type == 'phone' and _normalize_phone(ent.value) not in (scan.result_json or ''):
                    continue
            for placement in collect_geo_placements(payload, scan.module, scan.target):
                match = False
                if placement['entity_type'] == ent.entity_type:
                    pv = placement['value']
                    if ent.entity_type == 'phone':
                        match = _normalize_phone(pv) == _normalize_phone(ent.value)
                    elif ent.entity_type == 'domain':
                        match = _normalize_domain(pv) == _normalize_domain(ent.value)
                    else:
                        match = pv.lower() == ent.value.lower()
                if match:
                    if apply_geo_to_entity(
                        ent, placement['lat'], placement['lon'],
                        placement.get('label', ''), placement.get('source', 'scan-replay'),
                    ):
                        updated += 1
                    break
            if ent.latitude is not None:
                break
    return updated


def build_map_markers(
    entity_id: int, user_id: int, *,
    max_markers: int = 80,
    geocode_missing: bool = True,
    max_geocode_calls: int = 15,
    hydrate_from_scans: bool = True,
) -> dict:
    """Marqueurs Leaflet pour le sous-graphe d'une entité racine."""
    from services.correlation import build_graph_json

    root = Entity.query.filter_by(id=entity_id, user_id=user_id).first()
    if not root:
        return {'markers': [], 'root_entity_id': None, 'center': None}

    graph = build_graph_json(entity_id, user_id)
    node_ids = [int(n['id']) for n in graph.get('nodes', []) if n.get('id')][:max_markers]

    if hydrate_from_scans:
        try:
            hydrate_entities_from_scans(node_ids, user_id)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            logger.error(
                'Erreur commit hydrate map entity=%s user=%s: %s',
                entity_id, user_id, e,
            )

    markers = []
    geocode_budget = max_geocode_calls if geocode_missing else 0

    for nid in node_ids:
        ent = db.session.get(Entity, nid)
        if not ent or ent.user_id != user_id:
            continue
        loc = None
        precision = 'stored'
        if ent.latitude is not None and ent.longitude is not None:
            loc = {
                'lat': ent.latitude,
                'lon': ent.longitude,
                'label': ent.geo_label or ent.value,
                'source': ent.geo_source or 'stored',
            }
            precision = ent.geo_source or 'stored'
        elif geocode_budget > 0:
            loc = geolocate_entity(ent, allow_network=True)
            if loc:
                geocode_budget -= 1
                precision = loc.get('precision') or loc.get('source', 'network')
                try:
                    db.session.commit()
                except Exception as e:
                    db.session.rollback()
                    logger.error(
                        'Erreur commit géoloc entité %s (map entity=%s): %s',
                        nid, entity_id, e,
                    )
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
            'precision': precision,
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
