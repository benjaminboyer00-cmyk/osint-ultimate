"""Centroïdes pays (approximation) pour cartographie sans géocodage ville."""
import re
import unicodedata

# ISO 3166-1 alpha-2 → (lat, lon, libellé FR)
COUNTRY_CENTROIDS: dict[str, tuple[float, float, str]] = {
    'FR': (46.603354, 1.888334, 'France'),
    'US': (39.8283, -98.5795, 'États-Unis'),
    'GB': (55.3781, -3.4360, 'Royaume-Uni'),
    'DE': (51.1657, 10.4515, 'Allemagne'),
    'ES': (40.4637, -3.7492, 'Espagne'),
    'IT': (41.8719, 12.5674, 'Italie'),
    'BE': (50.5039, 4.4699, 'Belgique'),
    'CH': (46.8182, 8.2275, 'Suisse'),
    'CA': (56.1304, -106.3468, 'Canada'),
    'NL': (52.1326, 5.2913, 'Pays-Bas'),
    'PL': (51.9194, 19.1451, 'Pologne'),
    'PT': (39.3999, -8.2245, 'Portugal'),
    'BR': (-14.2350, -51.9253, 'Brésil'),
    'MX': (23.6345, -102.5528, 'Mexique'),
    'AR': (-38.4161, -63.6167, 'Argentine'),
    'AU': (-25.2744, 133.7751, 'Australie'),
    'JP': (36.2048, 138.2529, 'Japon'),
    'CN': (35.8617, 104.1954, 'Chine'),
    'IN': (20.5937, 78.9629, 'Inde'),
    'RU': (61.5240, 105.3188, 'Russie'),
    'UA': (48.3794, 31.1656, 'Ukraine'),
    'SE': (60.1282, 18.6435, 'Suède'),
    'NO': (60.4720, 8.4689, 'Norvège'),
    'DK': (56.2639, 9.5018, 'Danemark'),
    'FI': (61.9241, 25.7482, 'Finlande'),
    'IE': (53.4129, -8.2439, 'Irlande'),
    'AT': (47.5162, 14.5501, 'Autriche'),
    'LU': (49.8153, 6.1296, 'Luxembourg'),
    'MA': (31.7917, -7.0926, 'Maroc'),
    'DZ': (28.0339, 1.6596, 'Algérie'),
    'TN': (33.8869, 9.5375, 'Tunisie'),
    'SN': (14.4974, -14.4524, 'Sénégal'),
    'CI': (7.5400, -5.5471, 'Côte d\'Ivoire'),
    'ZA': (-30.5595, 22.9375, 'Afrique du Sud'),
    'EG': (26.8206, 30.8025, 'Égypte'),
    'IL': (31.0461, 34.8516, 'Israël'),
    'TR': (38.9637, 35.2433, 'Turquie'),
    'AE': (23.4241, 53.8478, 'Émirats arabes unis'),
    'SG': (1.3521, 103.8198, 'Singapour'),
    'HK': (22.3193, 114.1694, 'Hong Kong'),
    'KR': (35.9078, 127.7669, 'Corée du Sud'),
    'NZ': (-40.9006, 174.8860, 'Nouvelle-Zélande'),
    'RO': (45.9432, 24.9668, 'Roumanie'),
    'CZ': (49.8175, 15.4730, 'République tchèque'),
    'HU': (47.1625, 19.5033, 'Hongrie'),
    'GR': (39.0742, 21.8243, 'Grèce'),
}

# Noms / alias → code ISO2
_NAME_TO_ISO: dict[str, str] = {}
for code, (_, _, label) in COUNTRY_CENTROIDS.items():
    _NAME_TO_ISO[label.lower()] = code
    _NAME_TO_ISO[code.lower()] = code

_EXTRA_ALIASES = {
    'france': 'FR', 'états-unis': 'US', 'etats-unis': 'US', 'usa': 'US',
    'united states': 'US', 'united states of america': 'US', 'u.s.a.': 'US',
    'united kingdom': 'GB', 'uk': 'GB', 'great britain': 'GB', 'royaume-uni': 'GB',
    'germany': 'DE', 'allemagne': 'DE', 'deutschland': 'DE',
    'spain': 'ES', 'espagne': 'ES', 'italy': 'IT', 'italie': 'IT',
    'belgium': 'BE', 'belgique': 'BE', 'switzerland': 'CH', 'suisse': 'CH',
    'canada': 'CA', 'netherlands': 'NL', 'pays-bas': 'NL', 'holland': 'NL',
    'poland': 'PL', 'pologne': 'PL', 'portugal': 'PT', 'brazil': 'BR', 'brésil': 'BR',
    'mexico': 'MX', 'mexique': 'MX', 'australia': 'AU', 'australie': 'AU',
    'japan': 'JP', 'japon': 'JP', 'china': 'CN', 'chine': 'CN',
    'india': 'IN', 'inde': 'IN', 'russia': 'RU', 'russie': 'RU',
    'ukraine': 'UA', 'sweden': 'SE', 'suède': 'SE', 'norway': 'NO', 'norvège': 'NO',
    'denmark': 'DK', 'danemark': 'DK', 'finland': 'FI', 'finlande': 'FI',
    'ireland': 'IE', 'irlande': 'IE', 'austria': 'AT', 'autriche': 'AT',
    'morocco': 'MA', 'maroc': 'MA', 'algeria': 'DZ', 'algérie': 'DZ',
    'tunisia': 'TN', 'tunisie': 'TN', 'israel': 'IL', 'israël': 'IL',
    'turkey': 'TR', 'turquie': 'TR', 'singapore': 'SG', 'singapour': 'SG',
    'south korea': 'KR', 'corée du sud': 'KR', 'new zealand': 'NZ',
    'romania': 'RO', 'roumanie': 'RO', 'greece': 'GR', 'grèce': 'GR',
}
_NAME_TO_ISO.update(_EXTRA_ALIASES)


def _norm_name(s: str) -> str:
    s = (s or '').strip().lower()
    if not s or s in ('n/a', 'na', 'unknown', 'inconnu', '?', '-'):
        return ''
    s = unicodedata.normalize('NFKD', s)
    s = ''.join(c for c in s if not unicodedata.combining(c))
    return re.sub(r'\s+', ' ', s).strip()


def country_to_iso(country: str) -> str | None:
    """Convertit un libellé pays ou code ISO en ISO2."""
    raw = (country or '').strip()
    if not raw:
        return None
    if len(raw) == 2 and raw.upper() in COUNTRY_CENTROIDS:
        return raw.upper()
    key = _norm_name(raw)
    if not key:
        return None
    if key in _NAME_TO_ISO:
        return _NAME_TO_ISO[key]
    if key.upper() in COUNTRY_CENTROIDS:
        return key.upper()
    for alias, iso in _NAME_TO_ISO.items():
        if alias in key or key in alias:
            return iso
    return None


def coords_for_country(country: str) -> dict | None:
    """Retourne lat/lon/label pour un pays (précision « pays »)."""
    iso = country_to_iso(country)
    if not iso or iso not in COUNTRY_CENTROIDS:
        return None
    lat, lon, label = COUNTRY_CENTROIDS[iso]
    return {
        'lat': lat,
        'lon': lon,
        'label': label,
        'country': label,
        'iso': iso,
        'precision': 'country',
        'source': 'country-centroid',
    }
