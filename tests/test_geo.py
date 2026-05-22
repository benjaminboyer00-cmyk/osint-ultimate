"""Tests géolocalisation — Phase 5 V7."""
import sys
from unittest.mock import MagicMock, patch

from services.geo import (
    _valid_coords,
    fetch_ip_geolocation,
    apply_geo_to_entity,
    build_map_markers,
    _geo_from_scan_payload,
    collect_geo_placements,
    hydrate_entities_from_scans,
    IP_RE,
)
from services.country_geo import coords_for_country, country_to_iso


def test_valid_coords():
    assert _valid_coords(48.8, 2.3) is True
    assert _valid_coords(999, 2) is False
    assert _valid_coords('x', 2) is False


def test_ip_regex():
    assert IP_RE.match('8.8.8.8')
    assert not IP_RE.match('not-an-ip')


def test_geo_from_scan_payload_city():
    raw = {'Géolocalisation': {'Lat': 51.5, 'Lon': -0.1, 'Ville': 'London', 'Pays': 'UK'}}
    g = _geo_from_scan_payload(raw)
    assert g and g['lat'] == 51.5


def test_geo_from_scan_payload_country_only():
    raw = {'Pays': 'France'}
    g = _geo_from_scan_payload(raw)
    assert g and g['lat'] > 40
    assert g.get('precision') == 'country'


def test_country_france():
    assert country_to_iso('France') == 'FR'
    loc = coords_for_country('France')
    assert loc and loc['iso'] == 'FR'


def test_collect_geo_phone_scan():
    result = {
        'Pays': 'France',
        'Format E.164': '+33601020304',
        'Géolocalisation': {'Lat': 46.6, 'Lon': 1.9, 'Pays': 'France', 'Précision': 'Pays (indicatif téléphonique)'},
    }
    placements = collect_geo_placements(result, 'phone', '+33601020304')
    assert any(p['entity_type'] == 'phone' for p in placements)


def test_collect_geo_site_hosting():
    result = {
        'IP': '8.8.8.8',
        'Géolocalisation': {
            'Pays': 'United States', 'Ville': 'Ashburn',
            'Lat': 39.0, 'Lon': -77.0,
        },
    }
    placements = collect_geo_placements(result, 'site', 'example.com')
    types = {p['entity_type'] for p in placements}
    assert 'domain' in types


def test_fetch_ip_geolocation_mock():
    fake = {'status': 'success', 'lat': 40.7, 'lon': -74.0, 'city': 'NYC', 'country': 'US'}
    with patch('services.geo.requests.get') as mock_get:
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = fake
        with patch('services.cache.get_cached', return_value=None):
            with patch('services.cache.set_cached'):
                loc = fetch_ip_geolocation('8.8.8.8')
    assert loc['lat'] == 40.7


def test_apply_geo_to_entity():
    ent = MagicMock(latitude=None, longitude=None, geo_label=None, geo_source=None, value='1.2.3.4')
    with patch('services.geo.db') as mock_db:
        assert apply_geo_to_entity(ent, 1.0, 2.0, 'Test', 'ip-api') is True
    assert ent.latitude == 1.0
    mock_db.session.add.assert_called_with(ent)


def test_build_map_markers_empty():
    with patch('services.geo.Entity') as Ent:
        Ent.query.filter_by.return_value.first.return_value = None
        out = build_map_markers(99, 10, geocode_missing=False, hydrate_from_scans=False)
    assert out['markers'] == []
