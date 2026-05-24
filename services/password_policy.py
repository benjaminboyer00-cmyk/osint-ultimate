"""Politique de mots de passe — feedback zxcvbn optionnel."""
from __future__ import annotations


def password_strength(password: str) -> dict:
    """
    Retourne {score: 0-4, label, feedback, acceptable}.
    score < 2 → unacceptable pour inscription.
    """
    if not password or len(password) < 8:
        return {
            'score': 0,
            'label': 'Trop court',
            'feedback': ['Minimum 8 caractères'],
            'acceptable': False,
        }
    try:
        from zxcvbn import zxcvbn
        r = zxcvbn(password)
        score = int(r.get('score', 0))
        feedback = []
        for seq in (r.get('feedback') or {}).get('suggestions') or []:
            feedback.append(str(seq))
        for warn in (r.get('feedback') or {}).get('warning') or []:
            if warn:
                feedback.insert(0, str(warn))
        labels = ('Très faible', 'Faible', 'Moyen', 'Bon', 'Excellent')
        return {
            'score': score,
            'label': labels[min(score, 4)],
            'feedback': feedback[:5],
            'acceptable': score >= 2 and len(password) >= 10,
        }
    except ImportError:
        acceptable = len(password) >= 10 and any(c.isdigit() for c in password) and any(c.isalpha() for c in password)
        return {
            'score': 3 if acceptable else 1,
            'label': 'Acceptable' if acceptable else 'Faible',
            'feedback': ['Installez zxcvbn pour une analyse fine'] if not acceptable else [],
            'acceptable': acceptable,
        }
