"""Garde-fou : l'agent ne scanne pas de cibles descriptives inventées par le LLM."""
from services.investigation_agent import _is_concrete_target


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
