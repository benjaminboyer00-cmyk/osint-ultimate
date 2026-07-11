"""Garde-fou : l'agent ne scanne pas de cibles descriptives inventées par le LLM."""
from services.investigation_agent import (
    _is_concrete_target,
    _is_grounded_target,
    _grounded_values,
    _extract_identifiers,
)


def test_rejects_llm_placeholders():
    for bad in [
        'domaine_du_email_1_obtenu_grace_au_resultat_de_epieos',
        'pseudo_obtenu_a_partir_du_resultat_de_dehashed',
        'nom_de_la_personne', 'valeur_de_l_email', 'le domaine obtenu',
        'à déterminer', '',
    ]:
        assert not _is_concrete_target(bad), bad


def test_accepts_real_identifiers():
    for good in [
        'victoria.barros1815@gmail.com', 'benji', 'example.com', '8.8.8.8',
        '+33612345678', 'darkdev42', 'john.doe', 'my-site.co.uk',
    ]:
        assert _is_concrete_target(good), good


# ── Grounding : la cible doit être FONDÉE (objectif ou données découvertes) ──

def test_grounding_rejects_llm_invented_domains():
    """« pourdehashed.fr » / « dehashed.com » fabriqués par le LLM -> rejetés."""
    objective = "pour dehashed t'as trouvé quoi du coup pas besoin de refaire"
    known = _grounded_values(objective, None, None)
    assert not _is_grounded_target('pourdehashed.fr', objective, known)
    assert not _is_grounded_target('dehashed.com', objective, known)


def test_grounding_accepts_objective_email_and_its_domain():
    objective = "recherche tout ce que tu peux sur barros.victoria1815@gmail.com"
    known = _grounded_values(objective, None, None)
    assert _is_grounded_target('barros.victoria1815@gmail.com', objective, known)
    assert _is_grounded_target('gmail.com', objective, known)   # domaine de l'email


def test_grounding_rejects_common_words():
    objective = "recherche tout ce que tu peux sur la personne"
    known = _grounded_values(objective, None, None)
    # « peux » est un mot courant, jamais une cible à scanner
    assert not _is_grounded_target('peux', objective, known)


def test_extract_identifiers_ignores_common_words():
    ids = _extract_identifiers("recherche tout ce que tu peux de compte ou autre")
    assert 'peux' not in [u.lower() for u in ids['username']]
    assert 'autre' not in [u.lower() for u in ids['username']]
