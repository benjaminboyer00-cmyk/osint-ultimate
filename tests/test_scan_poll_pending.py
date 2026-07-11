"""Régression : pending_payload ne doit JAMAIS inclure d'objet non-sérialisable
(ex: _app = objet Flask) sinon json.dumps lève -> 500 sur /graph/scan-node."""
import json

from services.scan_poll import pending_payload


def test_strips_flask_app_and_non_serializable():
    class Dummy:  # objet non sérialisable (comme l'app Flask)
        pass
    opts = {
        '_app': Dummy(), '_socketio': Dummy(), '_fernet': Dummy(),
        '_root_entity_id': 5, '_stealth_mode': True, '_poll_token': 'tok',
        'weird': Dummy(), 'ok_list': [1, 2], 'ok_str': 'x',
    }
    payload = pending_payload(opts)
    # doit être sérialisable sans erreur
    json.dumps(payload)
    inner = payload['_pending_options']
    assert '_app' not in inner and '_socketio' not in inner and 'weird' not in inner
    assert inner['_root_entity_id'] == 5 and inner['_stealth_mode'] is True
    assert inner['ok_list'] == [1, 2] and inner['ok_str'] == 'x'
    assert payload['_poll_token'] == 'tok'
