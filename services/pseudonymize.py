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
    'url': 'URL',
    'platform': 'PLATFORM',
    'person': 'PERSONNE',
}

# Extraction d'identifiants dans du texte libre. Ordre = priorité (les
# catégories les plus spécifiques d'abord pour éviter les recouvrements).
# Le téléphone est volontairement strict (+intl ou 0X français) pour ne pas
# happer les années, ports, ou identifiants CVE.
_EXTRACTORS = [
    (re.compile(r'https?://[^\s"\'<>)\]}]+', re.I), 'url'),
    (re.compile(r'[\w.+-]+@[\w-]+(?:\.[\w-]+)+'), 'email'),
    (re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'), 'ip'),
    (re.compile(r'(?<![\w.+-])(?:\+\d[\d ().-]{7,}\d|0[1-9](?:[ .-]?\d{2}){4})'), 'phone'),
    (re.compile(r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b', re.I), 'domain'),
]


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

    def pseudonymize_text(self, text):
        """Remplace dans un texte libre les valeurs connues + les identifiants
        détectés (email, IP, domaine, URL, téléphone) par des jetons."""
        if not text:
            return text
        s = str(text)
        # 1) valeurs déjà enregistrées (contexte du caller), longues d'abord
        known = sorted(self._to_token.keys(), key=len, reverse=True)
        if known:
            kre = re.compile(
                r'(?<![\w.@-])(' + '|'.join(re.escape(k) for k in known) + r')(?![\w.@-])',
                re.I,
            )
            s = kre.sub(lambda m: self._to_token[m.group(1).lower()], s)
        # 2) extraction d'identifiants structurés
        for rx, etype in _EXTRACTORS:
            s = rx.sub(lambda m: self.token_for(m.group(0), etype), s)
        return s

    def pseudonymize_obj(self, obj):
        """Applique ``pseudonymize_text`` à toutes les chaînes d'une structure
        (les clés de dict — noms de champs — sont conservées telles quelles)."""
        if isinstance(obj, str):
            return self.pseudonymize_text(obj)
        if isinstance(obj, list):
            return [self.pseudonymize_obj(x) for x in obj]
        if isinstance(obj, dict):
            return {k: self.pseudonymize_obj(v) for k, v in obj.items()}
        return obj

    def rehydrate(self, obj):
        """Remplace les jetons par les vraies valeurs dans une structure JSON
        (ou une simple chaîne)."""
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
