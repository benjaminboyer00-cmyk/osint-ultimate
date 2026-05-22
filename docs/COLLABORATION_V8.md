# Phase 8 — Collaboration (V8)

## Correspondance spec ↔ code

| Cahier des charges | Table SQL (Supabase) | Modèle SQLAlchemy |
|--------------------|----------------------|-------------------|
| `dossier_collaborators` | `dossier_collaborator` | `DossierCollaborator` |
| `comments` | `entity_comment` | `EntityComment` |
| `activity_log` | `dossier_activity_log` | `DossierActivityLog` |
| — | `collaboration_notification` | `CollaborationNotification` |
| `dossier_id` | **`root_entity_id`** (FK → `entity.id`) | Pas de table `dossier` : le dossier = entité racine OSINT |

## Migration

```bash
flask db upgrade   # révision 011_v8_collaboration
```

Crée aussi la colonne `scan.root_entity_id` pour lier les scans au dossier partagé.

## Permissions (pas de JWT séparé)

- Authentification : **Flask-Login** + compte `User` existant.
- Autorisation : `services/dossier_access.py` — rôles `reader` / `editor` / `admin`.
- Propriétaire du dossier = `Entity.user_id` de l’entité racine.

## Invitations (sans email SMTP)

L'application **n'envoie pas d'email** pour les invitations. Après `POST /dossier/<id>/invite` :

1. Une ligne `dossier_collaborator` est créée (en attente).
2. Une notification in-app est ajoutée pour l'invité.
3. L'API renvoie `invite_url` (ex. `https://votre-app/invitations#inv-42`) à **copier manuellement**.

L'invité doit posséder un compte avec **le même email** que celui saisi à l'invitation.

## Routes principales

| Route | Rôle |
|-------|------|
| `POST /dossier/<entity_id>/invite` | admin |
| `GET /invitations` | invité |
| `POST /invitations/<id>/accept` | invité |
| `GET/POST /entity/<id>/comments` | reader+ |
| `GET /dossier/<id>/activity` | reader+ |
| `POST /expert/dossier/<id>/scan` | editor — lance un scan (suggestions Hunter/Wayback/WHOIS) |
| `POST /expert/dossier/<id>/narrative` | reader+ — rapport IA (JSON) |
| Socket `join_dossier` | reader accepté |

## Déduplication entités

Toute création d'entité lors de la corrélation passe par `services/entity_resolve.get_or_create_entity` (recherche exacte + `find_entity_for_target` avant insert). Les scans sur un dossier partagé utilisent le `user_id` du **propriétaire** du dossier (`correlation_user_id`).

## Supabase

Types utilisés : `INTEGER`, `VARCHAR`, `TEXT`, `BOOLEAN`, `TIMESTAMP` — compatibles PostgreSQL.
Pas de JSON natif requis (`details_json` en `TEXT`).

## Vérifier les tables en base

```sql
SELECT table_name FROM information_schema.tables
WHERE table_schema = 'public'
  AND table_name IN (
    'dossier_collaborator', 'entity_comment',
    'dossier_activity_log', 'collaboration_notification'
  );
```
