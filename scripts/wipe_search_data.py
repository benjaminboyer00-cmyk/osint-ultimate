#!/usr/bin/env python3
"""Réinitialise les DONNÉES DE RECHERCHE (repartir de zéro), sans toucher aux
comptes utilisateurs ni à leurs clés API/paramètres.

Supprime : scans, entités, liens, enquêtes, cache API, commentaires, activité
de dossier, collaborateurs, notifications, alertes, scans programmés.
Conserve : user, webhook, recipe.

Sécurité : ne s'exécute QUE si CONFIRM_WIPE=1 (ou argument --yes). Transaction
unique : en cas d'erreur, rollback total (rien n'est supprimé).

Usage :
    DATABASE_URL=postgresql://... CONFIRM_WIPE=1 python scripts/wipe_search_data.py
    # ou
    python scripts/wipe_search_data.py --yes
"""
import os
import sys


def _database_url() -> str | None:
    url = os.environ.get('DATABASE_URL')
    if not url and os.path.exists('.env'):
        for line in open('.env', encoding='utf-8'):
            line = line.strip()
            if line.startswith('DATABASE_URL=') and len(line) > 14:
                url = line.split('=', 1)[1].strip().strip('"').strip("'")
                break
    if url and url.startswith('postgres') and 'sslmode' not in url:
        url += ('&' if '?' in url else '?') + 'sslmode=require'
    return url


# Ordre respectant les clés étrangères (enfants -> parents).
_ORDER = [
    'collaboration_notification', 'dossier_activity_log', 'entity_comment',
    'dossier_collaborator', 'monitoring_alert', 'scheduled_scan',
    'investigation_message', 'investigation', 'entity_link', 'api_cache',
]


def main() -> int:
    if os.environ.get('CONFIRM_WIPE') != '1' and '--yes' not in sys.argv:
        print('Refusé : définissez CONFIRM_WIPE=1 ou passez --yes pour confirmer.')
        return 2
    url = _database_url()
    if not url:
        print('DATABASE_URL introuvable.')
        return 1

    import psycopg2
    conn = psycopg2.connect(url, connect_timeout=20)
    conn.autocommit = False
    cur = conn.cursor()
    try:
        deleted = {}
        for t in _ORDER:
            cur.execute(f'DELETE FROM {t}')
            deleted[t] = cur.rowcount
        # rupture du cycle scan <-> entity (FK nullables)
        cur.execute('UPDATE scan SET root_entity_id = NULL')
        cur.execute('UPDATE entity SET source_scan_id = NULL')
        cur.execute('DELETE FROM entity')
        deleted['entity'] = cur.rowcount
        cur.execute('DELETE FROM scan')
        deleted['scan'] = cur.rowcount
        conn.commit()
    except Exception as e:  # noqa: BLE001
        conn.rollback()
        print(f'ROLLBACK — rien supprimé. Erreur : {e}')
        return 1
    finally:
        cur.close()
        conn.close()

    total = sum(deleted.values())
    print(f'✅ Données de recherche réinitialisées ({total} lignes supprimées). Comptes conservés.')
    for k, v in deleted.items():
        if v:
            print(f'  {k:30} {v}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
