"""Préparation des données pour export PDF (volumes importants)."""
import json

MAX_SECTION_CHARS = 8000
MAX_SECTIONS = 30
MAX_TOTAL_CHARS = 180000
MAX_LIST_ITEMS = 40


def _truncate_value(obj, depth=0, max_depth=4):
    if depth > max_depth:
        return '…'
    if obj is None:
        return None
    if isinstance(obj, str):
        return obj[:2000] + ('…' if len(obj) > 2000 else '')
    if isinstance(obj, (int, float, bool)):
        return obj
    if isinstance(obj, list):
        trimmed = [_truncate_value(x, depth + 1, max_depth) for x in obj[:MAX_LIST_ITEMS]]
        if len(obj) > MAX_LIST_ITEMS:
            trimmed.append(f'… ({len(obj) - MAX_LIST_ITEMS} éléments omis)')
        return trimmed
    if isinstance(obj, dict):
        out = {}
        for i, (k, v) in enumerate(obj.items()):
            if i >= 50:
                out['_troncature'] = f'{len(obj) - 50} clés omises'
                break
            out[str(k)[:120]] = _truncate_value(v, depth + 1, max_depth)
        return out
    return str(obj)[:500]


def prepare_report_data(raw: dict) -> dict:
    """
    Réduit la taille du JSON pour WeasyPrint (évite PDF illisible ou OOM).
    Conserve _meta et les sections principales.
    """
    if not isinstance(raw, dict):
        return {}
    out = {}
    total = 0
    sections = [
        (k, v) for k, v in raw.items()
        if not str(k).startswith('_') or k == '_meta'
    ]
    for key, content in sections[:MAX_SECTIONS]:
        if key == '_meta':
            out[key] = content
            continue
        truncated = _truncate_value(content)
        blob = json.dumps(truncated, ensure_ascii=False, indent=2, default=str)
        if len(blob) > MAX_SECTION_CHARS:
            blob = blob[:MAX_SECTION_CHARS] + '\n… [section tronquée pour le PDF]'
        total += len(blob)
        if total > MAX_TOTAL_CHARS:
            out['_note_pdf'] = 'Rapport tronqué — exportez le JSON complet pour l’intégralité des données.'
            break
        try:
            out[key] = json.loads(blob)
        except Exception:
            out[key] = truncated
    if '_note_pdf' not in out and len(sections) > MAX_SECTIONS:
        out['_note_pdf'] = f'{len(sections) - MAX_SECTIONS} sections omises (limite PDF).'
    return out
