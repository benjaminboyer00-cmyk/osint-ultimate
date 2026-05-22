"""Tests alertes surveillance — Phase 7 V7."""
import json

from services.monitor_rules import parse_alert_rules, DEFAULT_RULES, RULE_IDS
from services.monitor_snapshot import build_monitor_snapshot, snapshot_to_json, snapshot_from_json
from services.monitoring_alerts import evaluate_snapshot_rules, compare_signals


def test_parse_alert_rules_default():
    assert 'threat_change' in parse_alert_rules(None)
    assert parse_alert_rules(json.dumps(['data_breach'])) == ['data_breach']


def test_build_snapshot_whois():
    result = {
        'WHOIS': {'Création': '2020-01-01', 'Registrar': 'Test Reg', 'Expiration': '2030-01-01'},
    }
    snap = build_monitor_snapshot(result, 'whois')
    assert snap['whois_hash']
    assert snap['whois']['registrar'] == 'Test Reg'


def test_evaluate_whois_change():
    prev = build_monitor_snapshot({'WHOIS': {'Création': '2020-01-01', 'Registrar': 'A'}}, 'whois')
    new = build_monitor_snapshot({'WHOIS': {'Création': '2021-01-01', 'Registrar': 'B'}}, 'whois')
    alerts = evaluate_snapshot_rules(prev, new, ['whois_change'])
    assert any(a['type'] == 'whois_change' for a in alerts)


def test_evaluate_data_breach():
    prev = build_monitor_snapshot({'Fuites (HIBP)': ['Adobe']}, 'email')
    new = build_monitor_snapshot({'Fuites (HIBP)': ['Adobe', 'LinkedIn']}, 'email')
    alerts = evaluate_snapshot_rules(prev, new, ['data_breach'])
    assert any(a['type'] == 'data_breach' for a in alerts)


def test_snapshot_roundtrip():
    snap = build_monitor_snapshot({'Module: ip': {'IP': '8.8.8.8'}}, 'multi')
    raw = snapshot_to_json(snap)
    back = snapshot_from_json(raw)
    assert back['threat_score'] == snap['threat_score']


def test_compare_signals_threat():
    prev = {'threat_score': 0, 'sections': {}, 'has_error': False}
    new = {'threat_score': 3, 'sections': {'otx': 3}, 'has_error': False}
    alerts = compare_signals(prev, new)
    assert any(a['type'] == 'threat_increase' for a in alerts)


def test_rule_ids_complete():
    for r in DEFAULT_RULES:
        assert r in RULE_IDS
