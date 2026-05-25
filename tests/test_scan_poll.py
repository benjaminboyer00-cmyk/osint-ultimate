"""Tests jeton polling scan."""
import json
from unittest.mock import MagicMock

from services.scan_poll import (
    attach_poll_token_to_result,
    new_poll_token,
    pending_payload,
    poll_token_valid,
)


def test_poll_token_roundtrip():
    tok = new_poll_token()
    scan = MagicMock()
    scan.result_json = json.dumps(pending_payload({'_poll_token': tok, 'x': 1}))
    assert poll_token_valid(scan, tok) is True
    assert poll_token_valid(scan, 'wrong') is False


def test_attach_poll_token_to_result():
    out = attach_poll_token_to_result({'Bio': 'x'}, 'abc123')
    assert out['_meta']['_poll_token'] == 'abc123'
