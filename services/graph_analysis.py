"""Analyse IA du graphe OSINT — au-delà du résumé.

L'IA reçoit les faits compacts du graphe (entités, liens, personnes
regroupées) et produit une *analyse* : synthèse, incohérences, hypothèses
de liens et pistes d'investigation priorisées. Dégrade proprement en une
analyse déterministe si aucun fournisseur LLM n'est disponible.

S'appuie sur la couche multi-fournisseur ``services.llm`` (robustesse +
cache) et sur le graphe unifié (clusters « même personne » de Phase 1).
"""
import json
import logging

from services.correlation import build_graph_json, get_rebound_suggestions
from services.entity_merge import MERGE_LINK_TYPE

logger = logging.getLogger(__name__)

MAX_ENTITIES = 60
MAX_LINKS = 80


def _token(entity_type: str, value: str) -> str:
    v = (value or '').lower().strip()
    if entity_type == 'email' and '@' in v:
        return v.split('@')[0]
    return v.lstrip('@')


def _clusters_from_graph(nodes: list, edges: list) -> list[list[str]]:
    """Composantes connexes sur les liens MEME_PERSONNE (personnes)."""
    idval = {n['id']: n.get('value') for n in nodes}
    adj: dict[str, list[str]] = {}
    for e in edges:
        if e.get('label') == MERGE_LINK_TYPE:
            adj.setdefault(str(e['source']), []).append(str(e['target']))
            adj.setdefault(str(e['target']), []).append(str(e['source']))
    seen = set()
    clusters = []
    for nid in adj:
        if nid in seen:
            continue
        comp, stack = [], [nid]
        seen.add(nid)
        while stack:
            cur = stack.pop()
            comp.append(cur)
            for nb in adj.get(cur, ()):
                if nb not in seen:
                    seen.add(nb)
                    stack.append(nb)
        vals = [idval.get(c) for c in comp if idval.get(c)]
        if len(vals) > 1:
            clusters.append(vals)
    return clusters


def build_analysis_payload(user_id: int, entity_id: int) -> dict:
    """Faits compacts du graphe pour l'IA (ou l'analyse déterministe)."""
    g = build_graph_json(entity_id, user_id)
    nodes = g.get('nodes', [])
    edges = g.get('edges', [])
    idval = {n['id']: n.get('value') for n in nodes}
    root_val = idval.get(g.get('root_id'))

    entities = [
        {'type': n.get('type'), 'valeur': n.get('value')}
        for n in nodes[:MAX_ENTITIES]
    ]
    links = []
    for e in edges[:MAX_LINKS]:
        links.append({
            'de': idval.get(str(e['source'])),
            'vers': idval.get(str(e['target'])),
            'type': e.get('label'),
            'confiance': e.get('confidence'),
        })
    return {
        'cible': root_val,
        'nb_entites': len(nodes),
        'nb_liens': len(edges),
        'entites': entities,
        'liens': links,
        'personnes_regroupees': _clusters_from_graph(nodes, edges),
        '_root_id': g.get('root_id'),
        '_empty': not nodes,
    }


_SYSTEM = (
    "Tu es un analyste OSINT senior. On te donne les faits d'un graphe "
    "d'investigation (entités, liens déduits, identifiants regroupés par "
    "personne). Tu ne résumes pas : tu ANALYSES. Réponds UNIQUEMENT en JSON "
    "valide, en français, avec exactement ces clés :\n"
    '{\n'
    '  "synthese": "2-4 phrases sur ce que révèle le graphe",\n'
    '  "personnes": [{"label": "nom/pseudo probable", "identifiants": ["..."], "note": "..."}],\n'
    '  "incoherences": [{"observation": "contradiction ou anomalie", "gravite": "faible|moyenne|elevee"}],\n'
    '  "liens_hypothetiques": [{"de": "valeur", "vers": "valeur", "hypothese": "...", "confiance": 0.0}],\n'
    '  "pistes": [{"action": "module + cible concrète", "raison": "...", "priorite": 1}]\n'
    '}\n'
    "N'invente pas de données absentes du graphe. Si une section est vide, "
    "renvoie une liste vide. Priorité : 1 = la plus urgente."
)


def _fallback_analysis(payload: dict, user_id: int) -> dict:
    """Analyse déterministe si aucun LLM disponible."""
    clusters = payload.get('personnes_regroupees') or []
    pistes = []
    try:
        root_id = payload.get('_root_id')
        if root_id:
            for s in get_rebound_suggestions(int(root_id), user_id)[:5]:
                pistes.append({
                    'action': f"{s['module']} sur {s['target']}",
                    'raison': s.get('reason', ''),
                    'priorite': 2,
                })
    except Exception as e:  # noqa: BLE001
        logger.debug('fallback pistes: %s', e)
    synth = (
        f"{payload.get('nb_entites', 0)} entités et "
        f"{payload.get('nb_liens', 0)} liens autour de « {payload.get('cible') or '?'} ». "
        + (f"{len(clusters)} personne(s) regroupée(s)." if clusters else '')
    )
    return {
        'synthese': synth.strip(),
        'personnes': [{'label': c[0], 'identifiants': c, 'note': ''} for c in clusters],
        'incoherences': [],
        'liens_hypothetiques': [],
        'pistes': pistes,
        'source': 'fallback',
    }


def _pseudonymize_facts(payload: dict, pseudo) -> dict:
    """Copie tokenisée des faits : aucune valeur réelle n'est envoyée à l'IA."""
    val_type = {
        e.get('valeur'): e.get('type')
        for e in payload.get('entites', []) if e.get('valeur')
    }

    def tok(v):
        return pseudo.token_for(v, val_type.get(v)) if v not in (None, '') else v

    return {
        'cible': tok(payload.get('cible')),
        'nb_entites': payload.get('nb_entites'),
        'nb_liens': payload.get('nb_liens'),
        'entites': [
            {'type': e.get('type'), 'valeur': tok(e.get('valeur'))}
            for e in payload.get('entites', [])
        ],
        'liens': [
            {'de': tok(l.get('de')), 'vers': tok(l.get('vers')),
             'type': l.get('type'), 'confiance': l.get('confiance')}
            for l in payload.get('liens', [])
        ],
        'personnes_regroupees': [
            [tok(v) for v in grp] for grp in payload.get('personnes_regroupees', [])
        ],
    }


def analyze_graph(user_id: int, entity_id: int) -> dict:
    """Analyse IA structurée du graphe (avec repli déterministe).

    Les identifiants réels sont pseudonymisés avant l'appel LLM et la réponse
    est ré-hydratée localement : le fournisseur ne voit que des jetons.
    """
    payload = build_analysis_payload(user_id, entity_id)
    if payload.get('_empty'):
        return {'error': 'Graphe vide — lancez d\'abord des scans.'}

    from services.pseudonymize import Pseudonymizer
    pseudo = Pseudonymizer()
    facts = json.dumps(
        _pseudonymize_facts(payload, pseudo),
        ensure_ascii=False, default=str,
    )[:9000]

    try:
        from services.llm import chat_json
        out = chat_json(
            f"Faits du graphe (JSON) :\n{facts}\n\n"
            "Analyse ce graphe et réponds en JSON selon le format imposé.",
            system=_SYSTEM, max_tokens=1600,
        )
        if isinstance(out, dict) and out.get('synthese'):
            out = pseudo.rehydrate(out)  # rétablit les vraies valeurs côté serveur
            out.setdefault('personnes', [])
            out.setdefault('incoherences', [])
            out.setdefault('liens_hypothetiques', [])
            out.setdefault('pistes', [])
            out['source'] = 'ia'
            return out
        logger.info('analyze_graph: réponse IA inexploitable, repli déterministe')
    except ValueError:
        pass  # aucun fournisseur configuré
    except Exception as e:  # noqa: BLE001
        logger.warning('analyze_graph IA: %s', e)

    return _fallback_analysis(payload, user_id)


def compare_graphs(user_id: int, entity_id_a: int, entity_id_b: int) -> dict:
    """Compare deux graphes : recouvrement d'identifiants + verdict IA."""
    ga = build_analysis_payload(user_id, entity_id_a)
    gb = build_analysis_payload(user_id, entity_id_b)
    if ga.get('_empty') or gb.get('_empty'):
        return {'error': 'Un des deux graphes est vide.'}

    def tokens(payload):
        return {
            _token(e.get('type'), e.get('valeur'))
            for e in payload.get('entites', [])
            if _token(e.get('type'), e.get('valeur'))
        }

    ta, tb = tokens(ga), tokens(gb)
    shared = sorted(ta & tb)
    union = ta | tb
    similarity = round(len(shared) / len(union), 3) if union else 0.0

    result = {
        'cible_a': ga.get('cible'),
        'cible_b': gb.get('cible'),
        'identifiants_partages': shared,
        'similarite': similarity,
    }

    try:
        from services.llm import chat_json
        from services.pseudonymize import Pseudonymizer
        pseudo = Pseudonymizer()

        def tok_entities(payload):
            vt = {e.get('valeur'): e.get('type')
                  for e in payload.get('entites', []) if e.get('valeur')}
            return [
                {'type': e.get('type'),
                 'valeur': pseudo.token_for(e.get('valeur'), vt.get(e.get('valeur')))}
                for e in payload.get('entites', [])
            ]

        ea, eb = tok_entities(ga), tok_entities(gb)                 # tokens (types connus)
        shared_tok = [pseudo.token_for(s) for s in shared]         # réutilise les mêmes jetons
        cible_a_tok, cible_b_tok = pseudo.token_for(ga.get('cible')), pseudo.token_for(gb.get('cible'))

        verdict = chat_json(
            "Deux graphes OSINT.\n"
            f"Graphe A (cible {cible_a_tok}) entités : "
            f"{json.dumps(ea, ensure_ascii=False)[:2500]}\n"
            f"Graphe B (cible {cible_b_tok}) entités : "
            f"{json.dumps(eb, ensure_ascii=False)[:2500]}\n"
            f"Identifiants en commun : {shared_tok}\n"
            "Ces deux graphes concernent-ils la même personne ou des personnes "
            "liées ? Réponds en JSON : "
            '{"verdict": "meme_personne|lies|distincts|incertain", '
            '"confiance": 0.0, "explication": "1-2 phrases"}',
            system="Tu es un analyste OSINT. Réponds uniquement en JSON valide.",
            fast=True, max_tokens=300,
        )
        if isinstance(verdict, dict) and verdict.get('verdict'):
            result['analyse_ia'] = pseudo.rehydrate(verdict)       # vraies valeurs rétablies
            result['source'] = 'ia'
            return result
    except ValueError:
        pass
    except Exception as e:  # noqa: BLE001
        logger.warning('compare_graphs IA: %s', e)

    result['analyse_ia'] = {
        'verdict': 'lies' if similarity >= 0.15 else ('incertain' if shared else 'distincts'),
        'confiance': similarity,
        'explication': (
            f"{len(shared)} identifiant(s) en commun (similarité {similarity})."
            if shared else 'Aucun identifiant commun détecté.'
        ),
    }
    result['source'] = 'fallback'
    return result
