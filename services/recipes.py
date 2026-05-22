"""Recettes d'investigation — builtins + persistance utilisateur."""
import json
from datetime import datetime

from extensions import db
from models import Recipe
from services.target_detector import target_category, detect_target_type

# Recettes officielles (non stockées en base)
BUILTIN_RECIPES = [
    {
        'id': 'builtin-email-full',
        'builtin': True,
        'name': 'Email — investigation complète',
        'description': 'Analyse technique, fuites Dehashed, Hunter (domaine), Epieos.',
        'target_types': ['email'],
        'modules': ['email', 'dehashed', 'hunter', 'epieos'],
        'author': 'OSINT Ultimate',
        'is_public': True,
        'usage_count': 0,
    },
    {
        'id': 'builtin-domain-infra',
        'builtin': True,
        'name': 'Domaine — infrastructure',
        'description': 'Site, WHOIS, archives Wayback, emails Hunter.',
        'target_types': ['domain', 'site'],
        'modules': ['site', 'whois', 'wayback', 'hunter'],
        'author': 'OSINT Ultimate',
        'is_public': True,
        'usage_count': 0,
    },
    {
        'id': 'builtin-pseudo-footprint',
        'builtin': True,
        'name': 'Pseudo — empreinte numérique',
        'description': 'Sherlock multi-plateformes, GitHub, fuites Dehashed.',
        'target_types': ['pseudo', 'username'],
        'modules': ['sherlock', 'github', 'dehashed'],
        'author': 'OSINT Ultimate',
        'is_public': True,
        'usage_count': 0,
    },
    {
        'id': 'builtin-phone-osint',
        'builtin': True,
        'name': 'Téléphone — OSINT',
        'description': 'Validation téléphone, messageries, fuites.',
        'target_types': ['phone'],
        'modules': ['phone', 'messaging', 'dehashed'],
        'author': 'OSINT Ultimate',
        'is_public': True,
        'usage_count': 0,
    },
    {
        'id': 'builtin-ip-recon',
        'builtin': True,
        'name': 'IP — reconnaissance',
        'description': 'Analyse IP/Shodan et WHOIS inverse.',
        'target_types': ['ip'],
        'modules': ['ip', 'whois'],
        'author': 'OSINT Ultimate',
        'is_public': True,
        'usage_count': 0,
    },
    {
        'id': 'builtin-threat-check',
        'builtin': True,
        'name': 'Menace — IOC check',
        'description': 'Vérification OTX + URLhaus (IP, domaine, URL).',
        'target_types': ['ip', 'domain', 'site'],
        'modules': ['otx', 'urlhaus'],
        'author': 'OSINT Ultimate',
        'is_public': True,
        'usage_count': 0,
    },
]


def _recipe_to_dict(r: Recipe, username: str = '') -> dict:
    modules = json.loads(r.modules_json or '[]')
    types = json.loads(r.target_types or '[]')
    return {
        'id': r.id,
        'builtin': False,
        'name': r.name,
        'description': r.description or '',
        'target_types': types,
        'modules': modules,
        'is_public': r.is_public,
        'author': username,
        'usage_count': r.usage_count or 0,
        'owner_id': r.user_id,
        'created_at': r.created_at.isoformat() if r.created_at else None,
    }


def list_recipes(user_id: int | None = None, include_community: bool = True) -> list[dict]:
    """Liste recettes builtin + utilisateur + communauté publique."""
    out = [dict(b) for b in BUILTIN_RECIPES]

    if user_id:
        mine = Recipe.query.filter_by(user_id=user_id).order_by(Recipe.updated_at.desc()).all()
        for r in mine:
            out.append(_recipe_to_dict(r, ''))

    if include_community:
        q = Recipe.query.filter_by(is_public=True)
        if user_id:
            q = q.filter(Recipe.user_id != user_id)
        for r in q.order_by(Recipe.usage_count.desc()).limit(50).all():
            author = ''
            if r.owner:
                author = r.owner.username
            out.append(_recipe_to_dict(r, author))

    return out


def get_recipe(recipe_ref: str | int, user_id: int | None = None) -> dict | None:
    """Récupère une recette par id builtin (str) ou id DB (int)."""
    if isinstance(recipe_ref, str) and recipe_ref.startswith('builtin-'):
        for b in BUILTIN_RECIPES:
            if b['id'] == recipe_ref:
                return dict(b)
        return None

    rid = int(recipe_ref)
    r = db.session.get(Recipe, rid)
    if not r:
        return None
    if not r.is_public and r.user_id != user_id:
        return None
    author = r.owner.username if r.owner else ''
    return _recipe_to_dict(r, author)


def create_recipe(user_id: int, data: dict) -> Recipe:
    modules = data.get('modules') or []
    if not modules:
        raise ValueError('Au moins un module requis')
    r = Recipe(
        user_id=user_id,
        name=(data.get('name') or 'Ma recette')[:120],
        description=(data.get('description') or '')[:2000],
        target_types=json.dumps(data.get('target_types') or [], ensure_ascii=False),
        modules_json=json.dumps(modules, ensure_ascii=False),
        is_public=bool(data.get('is_public')),
    )
    db.session.add(r)
    db.session.commit()
    return r


def update_recipe(recipe_id: int, user_id: int, data: dict) -> Recipe | None:
    r = db.session.get(Recipe, recipe_id)
    if not r or r.user_id != user_id:
        return None
    if 'name' in data:
        r.name = str(data['name'])[:120]
    if 'description' in data:
        r.description = str(data['description'])[:2000]
    if 'modules' in data:
        r.modules_json = json.dumps(data['modules'], ensure_ascii=False)
    if 'target_types' in data:
        r.target_types = json.dumps(data['target_types'], ensure_ascii=False)
    if 'is_public' in data:
        r.is_public = bool(data['is_public'])
    r.updated_at = datetime.utcnow()
    db.session.commit()
    return r


def delete_recipe(recipe_id: int, user_id: int) -> bool:
    r = db.session.get(Recipe, recipe_id)
    if not r or r.user_id != user_id:
        return False
    db.session.delete(r)
    db.session.commit()
    return True


def fork_recipe(recipe_ref: str | int, user_id: int) -> Recipe | None:
    src = get_recipe(recipe_ref, user_id)
    if not src:
        return None
    return create_recipe(user_id, {
        'name': f"{src['name']} (copie)",
        'description': src.get('description'),
        'target_types': src.get('target_types'),
        'modules': src.get('modules'),
        'is_public': False,
    })


def recipe_matches_target(recipe: dict, target: str) -> bool:
    types = recipe.get('target_types') or []
    if not types or '*' in types:
        return True
    cat = target_category(target)
    mod = detect_target_type(target)
    return cat in types or mod in types


def launch_recipe(recipe_ref: str | int, target: str, user_id: int | None, mode: str = 'expert'):
    """
    Lance un scan multi avec les modules de la recette.
    Retourne scan_id ou lève ValueError.
    """
    from app import run_scan_async, SCAN_FUNCTIONS

    recipe = get_recipe(recipe_ref, user_id)
    if not recipe:
        raise ValueError('Recette introuvable')

    target = (target or '').strip()
    if not target:
        raise ValueError('Cible manquante')

    if not recipe_matches_target(recipe, target):
        raise ValueError(
            f"Type de cible incompatible. Types attendus : {', '.join(recipe.get('target_types') or [])}"
        )

    modules = [m for m in (recipe.get('modules') or []) if m in SCAN_FUNCTIONS]
    if not modules:
        raise ValueError('Aucun module installé pour cette recette')

    options = {
        '_scan_mode': mode,
        '_category': target_category(target),
        '_modules': modules,
        '_recipe_id': str(recipe_ref),
        '_recipe_name': recipe.get('name'),
    }

    scan_id = run_scan_async('multi', target, options, user_id, mode=mode)
    if not scan_id:
        raise ValueError('Échec du lancement')

    if not recipe.get('builtin'):
        r = db.session.get(Recipe, int(recipe_ref))
        if r:
            r.usage_count = (r.usage_count or 0) + 1
            db.session.commit()

    return scan_id, recipe
