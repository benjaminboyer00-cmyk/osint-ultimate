"""Pseudonymisation des données avant envoi à un LLM tiers.

Objectif de confidentialité : un fournisseur d'IA externe ne doit **jamais**
recevoir d'identifiant réel (pseudo, email, téléphone, domaine…). On remplace
localement chaque valeur par un jeton neutre (``USERNAME_1``, ``EMAIL_2``…),
l'IA raisonne sur la *structure* (liens, incohérences, pistes), puis on
ré-hydrate sa réponse côté serveur avec les vraies valeurs.

L'IA reçoit donc « USERNAME_1 est lié à EMAIL_2 » et jamais « benji /
x@gmail.com ». Comme le mapping est reconstruit à chaque appel et appliqué
localement, deux graphes de structure identique produisent le même prompt
tokenisé (bon pour le cache) tout en étant ré-hydratés avec leurs propres
valeurs — aucune fuite croisée possible.
"""
import re

_TYPE_PREFIX = {
    'email': 'EMAIL',
    'phone': 'PHONE',
    'username': 'USERNAME',
    'domain': 'DOMAIN',
    'ip': 'IP',
    'platform': 'PLATFORM',
    'person': 'PERSONNE',
}


class Pseudonymizer:
    """Mapping bidirectionnel valeur réelle ↔ jeton neutre (par instance)."""

    def __init__(self):
        self._to_token: dict[str, str] = {}   # valeur (minuscule) -> jeton
        self._to_value: dict[str, str] = {}   # jeton -> valeur (casse d'origine)
        self._counter = 0

    def token_for(self, value, entity_type: str | None = None):
        """Jeton stable pour une valeur (même valeur -> même jeton)."""
        if value is None or value == '':
            return value
        v = str(value)
        key = v.lower()
        existing = self._to_token.get(key)
        if existing:
            return existing
        self._counter += 1
        prefix = _TYPE_PREFIX.get((entity_type or '').lower(), 'ENTITE')
        token = f'{prefix}_{self._counter}'
        self._to_token[key] = token
        self._to_value[token] = v
        return token

    def rehydrate(self, obj):
        """Remplace les jetons par les vraies valeurs dans une structure JSON."""
        if not self._to_value:
            return obj
        # jetons triés par longueur décroissante + \b : pas de collision
        # USERNAME_1 vs USERNAME_10 (la frontière de mot protège déjà, mais
        # on reste défensif).
        pattern = re.compile(
            r'\b(' + '|'.join(
                re.escape(t) for t in sorted(self._to_value, key=len, reverse=True)
            ) + r')\b'
        )

        def sub_str(s: str) -> str:
            return pattern.sub(lambda m: self._to_value[m.group(1)], s)

        def walk(o):
            if isinstance(o, str):
                return sub_str(o)
            if isinstance(o, list):
                return [walk(x) for x in o]
            if isinstance(o, dict):
                return {k: walk(v) for k, v in o.items()}
            return o

        return walk(obj)
