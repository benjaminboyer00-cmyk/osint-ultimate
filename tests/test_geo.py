"""Tests géolocalisation — Phase 5 V7."""
import sys
from unittest.mock import MagicMock, patch

from services.geo import (
    _valid_coords,
    fetch_ip_geolocation,
    apply_geo_to_entity,
    build_map_markers,
    _geo_from_scan_payload,
    IP_RE,
)


def test_valid_coords():
    assert _valid_coords(48.8, 2.3) is True
    assert _valid_coords(999, 2) is False
    assert _valid_coords('x', 2) is False


def test_ip_regex():
    assert IP_RE.match('8.8.8.8')
    assert not IP_RE.match('not-an-ip')


def test_geo_from_scan_payload():
    raw = {'Géolocalisation': {'Lat': 51.5, 'Lon': -0.1, 'Ville': 'London', 'Pays': 'UK'}}
    g = _geo_from_scan_payload(raw)
    assert g and g['lat'] == 51.5


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
        out = build_map_markers(99, 10)
    assert out['markers'] == []
