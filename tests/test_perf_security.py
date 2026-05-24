"""Tests performance / sécurité (circuit breaker, pagination)."""
from services.circuit_breaker import is_open, record_failure, record_success, breaker_open_response
from services.pagination import paginate_query
def test_circuit_breaker_opens_after_failures():
    record_success('test_provider')
    for _ in range(3):
        record_failure('test_provider', threshold=3, cooldown_sec=60)
    assert is_open('test_provider')
    resp = breaker_open_response('test_provider')
    assert resp.get('_circuit_open')


def test_paginate_query_structure():
    class FakeQuery:
        def count(self):
            return 100
        def offset(self, n):
            return self
        def limit(self, n):
            return self
        def all(self):
            return [1, 2, 3]
    out = paginate_query(FakeQuery(), page=2, per_page=25)
    assert out['page'] == 2
    assert out['total'] == 100
    assert out['has_prev'] is True
