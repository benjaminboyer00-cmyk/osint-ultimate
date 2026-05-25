"""Pivot graphe — extension d'enquête depuis un nœud (Phase 2)."""
import logging

from extensions import db
from models import Entity

logger = logging.getLogger(__name__)

# Modules OSINT par type d'entité
PIVOT_MODULES = {
    'email': ['email', 'dehashed', 'hunter', 'epieos'],
    'phone': ['phone', 'dehashed', 'messaging'],
    'username': ['sherlock', 'github', 'dehashed'],
    'platform': ['sherlock', 'pseudo'],
    'domain': ['site', 'whois', 'wayback', 'hunter'],
    'ip': ['ip', 'otx', 'urlhaus', 'whois'],
    'url': ['site', 'wayback'],
    'document': ['site', 'wayback'],
    'unknown': ['sherlock', 'site'],
}


def modules_for_entity(entity_type: str, value: str) -> list[str]:
    """Liste des modules à lancer pour un pivot."""
    from services.target_detector import detect_target_type, target_category
    from scans.registry import SCAN_FUNCTIONS

    etype = (entity_type or 'unknown').lower()
    mods = list(PIVOT_MODULES.get(etype, PIVOT_MODULES['unknown']))
    cat = target_category(value or '')
    if cat == 'email' and 'email' not in mods:
        mods = PIVOT_MODULES['email'] + mods
    if cat == 'domain' and etype not in ('domain',):
        for m in ('site', 'whois', 'wayback'):
            if m not in mods:
                mods.insert(0, m)
    return [m for m in mods if m in SCAN_FUNCTIONS][:6]


def launch_pivot(
    user_id: int,
    entity_id: int,
    *,
    root_entity_id: int | None = None,
    deep_dorking: bool = False,
    stealth: bool = False,
) -> dict:
    """
    Lance un scan multi-modules sur l'entité cible.
    Retourne {scan_id, modules, target, status} ou lève ValueError.
    """
    from services.dossier_access import get_dossier_context
    from services.correlation import build_graph_json

    ent = db.session.get(Entity, entity_id)
    if not ent:
        raise ValueError('Entité non trouvée')

    root_check = int(root_entity_id or entity_id)
    ctx = get_dossier_context(root_check, user_id, min_role='editor')
    if not ctx:
        raise ValueError('Droits insuffisants (éditeur requis)')

    graph = build_graph_json(root_check, ctx['owner_user_id'])
    node_ids = {int(n['id']) for n in graph.get('nodes', []) if n.get('id')}
    if entity_id not in node_ids and entity_id != root_check:
        raise ValueError('Entité hors du dossier partagé')

    from services.target_detector import target_category
    from app import run_scan_async
    from scans.registry import SCAN_FUNCTIONS

    modules = modules_for_entity(ent.entity_type, ent.value)
    if not modules:
        raise ValueError('Aucun module disponible pour ce type')

    root = int(root_entity_id or entity_id)
    opts = {
        '_modules': modules,
        '_category': target_category(ent.value),
        '_scan_mode': 'expert',
        '_root_entity_id': root,
        '_graph_pivot': True,
        '_graph_pivot_notify': str(user_id),
        '_from_graph': True,
    }
    if deep_dorking:
        opts['_deep_dorking'] = True
    if stealth:
        opts['_stealth_mode'] = True
    try:
        from flask import has_request_context, current_app
        if has_request_context():
            opts['_app'] = current_app._get_current_object()
    except Exception:
        pass

    from services.scan_poll import ensure_poll_token
    poll_token = ensure_poll_token(opts)
    scan_id = run_scan_async('multi', ent.value, opts, user_id=user_id, mode='expert')
    if not scan_id:
        raise ValueError('Échec du lancement du pivot')

    logger.info('Pivot user=%s entity=%s scan=%s modules=%s', user_id, entity_id, scan_id, modules)
    return {
        'scan_id': scan_id,
        'poll_token': poll_token,
        'status': 'started',
        'modules': modules,
        'target': ent.value,
        'entity_type': ent.entity_type,
        'root_entity_id': root,
        'poll_url': f'/scan/{scan_id}',
    }


def emit_graph_update_after_scan(scan, socketio, opts: dict):
    """Après un pivot terminé : pousse le graphe mis à jour via Socket.IO."""
    if not socketio or not scan or not scan.user_id:
        return
    root_id = opts.get('_root_entity_id')
    if not root_id:
        return

    try:
        from services.correlation import build_graph_json
        g = build_graph_json(int(root_id), scan.user_id)
        room = str(opts.get('_graph_pivot_notify') or scan.user_id)
        socketio.emit('graph_update', {
            'scan_id': scan.id,
            'root_entity_id': root_id,
            'nodes': g.get('nodes', []),
            'edges': g.get('edges', []),
            'message': f'Pivot terminé — scan #{scan.id}',
        }, room=room)
        logger.info('graph_update émis scan=%s root=%s', scan.id, root_id)
    except Exception as e:
        logger.warning('graph_update: %s', e)
