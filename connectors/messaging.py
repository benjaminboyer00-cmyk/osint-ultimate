"""Vérifications messagerie — sources publiques uniquement (respect ToS)."""
import re
from services.http_client import safe_get


def check_phone_presence(phone_e164: str, options=None) -> dict:
    """Indications publiques de présence (sans accès aux apps)."""
    phone = re.sub(r'\D', '', phone_e164)
    results = {'Numéro': phone_e164, 'Note': 'Vérifications indicatives — pas d\'accès aux comptes privés'}

    # WhatsApp click-to-chat (lien public)
    wa_url = f'https://wa.me/{phone}'
    r = safe_get(wa_url, options=options, timeout=10, allow_redirects=True)
    results['WhatsApp (lien wa.me)'] = 'Lien généré ✓' if r and r.status_code < 400 else 'Inaccessible'
    results['WhatsApp URL'] = wa_url

    # Telegram — t.me pour numéros (limité)
    tg = safe_get(f'https://t.me/+{phone}', options=options, timeout=8)
    results['Telegram (t.me)'] = 'Réponse HTTP ' + str(tg.status_code) if tg else 'Timeout'

    results['Signal'] = 'Aucune API publique — vérification manuelle requise'
    results['Avertissement'] = 'Usage conforme aux CGU des plateformes. Ne pas harceler.'
    return results
