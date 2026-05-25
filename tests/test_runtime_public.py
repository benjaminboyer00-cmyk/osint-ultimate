"""Tests infos runtime publiques."""
import os
from unittest.mock import patch

from services.runtime_public import public_runtime_info


def test_public_runtime_info_keys():
    with patch.dict(os.environ, {'SPACE_ID': 'benji/test'}, clear=False):
        info = public_runtime_info()
    assert 'hf_space' in info
    assert 'socket_io' in info
    assert 'instagram_mode' in info
    assert info['hf_space'] is True
    assert info['socket_io'] is False


def test_api_runtime_route(client):
    r = client.get('/api/runtime')
    assert r.status_code == 200
    data = r.get_json()
    assert 'version' in data
    assert 'hf_space' in data
