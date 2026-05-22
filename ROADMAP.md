# Feuille de route OSINT Ultimate — V4 → V5

> Document de référence produit & technique.  
> Projet : [Hugging Face Space](https://huggingface.co/spaces/benji4565/osint_ultimate_backend) · [Supabase](https://supabase.com/dashboard/project/mkciozumxpxllsjmcsyz)

## Vision

**Un seul outil, deux parcours** : recherche express pour le grand public, cockpit expert pour les investigations professionnelles (corrélation, graphes, API, rapports).

---

## État actuel (V4.0 — livré)

| Composant | Statut |
|-----------|--------|
| Flask 3 + Supabase PostgreSQL + migrations Alembic | ✅ |
| Auth (inscription, login, historique) | ✅ |
| 12+ modules de scan (site, email, phone, IP, réseaux sociaux…) | ✅ |
| Socket.IO + worker async | ✅ |
| Résumé IA OpenRouter (cache en base) | ✅ |
| Export JSON + PDF (WeasyPrint) | ✅ |
| Déploiement Docker / HF Spaces | ✅ |

---

## Phase 1 — Fondations & Quick Wins (2–4 semaines)

### 1.1 Interface duale Express / Expert

| ID | Tâche | Priorité | Statut |
|----|-------|----------|--------|
| P1.1.1 | Page `/express` — champ unique, détection auto du type | P0 | ✅ |
| P1.1.2 | Page `/expert` — console multi-modules actuelle | P0 | ✅ |
| P1.1.3 | Navigation croisée Express ↔ Expert | P0 | ✅ |
| P1.1.4 | Carte de synthèse Express (highlights, risques) | P0 | ✅ |
| P1.1.5 | Assistant IA pédagogique Express (`/express/assist`) | P1 | ✅ |
| P1.1.6 | Tuiles dédiées par type (téléphone, email, pseudo…) | P2 | 🔲 |

**User stories**
- *Lambda* : « Je colle un numéro, je clique Analyser, je comprends le résultat sans jargon. »
- *Expert* : « J’accède à tous les modules, l’historique, l’API et les exports bruts. »

### 1.2 Nouvelles sources

| ID | Tâche | Priorité | Statut |
|----|-------|----------|--------|
| P1.2.1 | Module `sherlock` (CLI + repli scan_pseudo) | P0 | ✅ |
| P1.2.2 | Shodan enrichi (bannières, CVE, services) | P0 | ✅ |
| P1.2.3 | Cache TTL résultats Sherlock (table `scan_cache`) | P2 | 🔲 |
| P1.2.4 | Hunter.io (emails pro par domaine) | P2 | 🔲 |
| P1.2.5 | Epieos | P3 | 🔲 |
| P1.2.6 | Dehashed (fuites) | P2 | 🔲 |
| P1.2.7 | BuiltWith (technos site) | P3 | 🔲 |

### 1.3 Rapports

| ID | Tâche | Priorité | Statut |
|----|-------|----------|--------|
| P1.3.1 | Bouton PDF Express + Expert | P0 | ✅ |
| P1.3.2 | PDF avec résumé IA + horodatage + sources | P1 | ✅ |
| P1.3.3 | Export CSV structuré | P2 | 🔲 |
| P1.3.4 | Signature / horodatage légal | P3 | 🔲 |

---

## Phase 2 — IA & corrélation (4–8 semaines)

### 2.1 Assistant IA

| ID | Tâche | Priorité | Statut |
|----|-------|----------|--------|
| P2.1.1 | Prompt Express pédagogique + prochaines étapes | P0 | ✅ |
| P2.1.2 | Rapport contextuel multi-sources (Expert) | P1 | 🔲 |
| P2.1.3 | Choix modèle IA via secret `OPENROUTER_MODEL` | P2 | 🔲 |
| P2.1.4 | Chat investigation (historique conversation) | P3 | 🔲 |

### 2.2 Moteur de corrélation

| ID | Tâche | Priorité | Statut |
|----|-------|----------|--------|
| P2.2.1 | Tables `entity` + `entity_link` | P0 | ✅ |
| P2.2.2 | Règle email → pseudo local → scan sherlock | P0 | ✅ |
| P2.2.3 | Règle phone → formats normalisés | P1 | ✅ |
| P2.2.4 | File de corrélation async (Celery) | P2 | 🔲 |
| P2.2.5 | Score de confiance par lien | P2 | 🔲 |

---

## Phase 3 — Visualisation (6–10 semaines)

| ID | Tâche | Priorité | Statut |
|----|-------|----------|--------|
| P3.1.1 | API `GET /api/v1/entity/<id>/graph` | P0 | ✅ |
| P3.1.1b | API `GET /api/v1/entity/<id>/links` | P0 | ✅ |
| P3.1.2 | Vue graphe Cytoscape.js (Expert) | P1 | ✅ |
| P3.1.3 | Clic nœud → relancer scan | P2 | 🔲 |
| P3.2.1 | Dossier investigation (timeline) | P2 | 🔲 |
| P3.2.2 | Ajout manuel d’entités | P2 | 🔲 |
| P3.2.3 | Filtres historique avancés | P3 | 🔲 |

---

## Phase 4 — API & automatisation (8–12 semaines)

| ID | Tâche | Priorité | Statut |
|----|-------|----------|--------|
| P4.1.1 | `POST /api/v1/search` | P0 | ✅ |
| P4.1.2 | `GET /api/v1/results/{id}` | P0 | ✅ |
| P4.1.3 | Auth par clé API (`X-API-Key` + Bearer) | P0 | ✅ |
| P4.1.6 | `GET /api/v1/me` — vérifier token | P1 | ✅ |
| P4.1.4 | OpenAPI `/api/docs` | P0 | ✅ |
| P4.1.5 | `GET /api/v1/export/{id}/pdf` | P1 | ✅ |
| P4.2.1 | Page `/settings` clés API utilisateur | P0 | ✅ |
| P4.3.1 | Scans programmés (APScheduler) | P3 | ✅ |
| P4.3.2 | Notifications email changements | P3 | 🔲 |

---

## Phase 5 — Communauté, OPSEC, scale (continu)

| ID | Tâche | Priorité | Statut |
|----|-------|----------|--------|
| P5.1.1 | Blueprints Flask par connecteur | P1 | 🔶 |
| P5.1.2 | Guide `CONTRIBUTING.md` + template connecteur | P2 | 🔲 |
| P5.2.1 | Proxy rotatif utilisateur (`PROXY_LIST`) | P1 | ✅ |
| P5.2.2 | Mode furtif (délais aléatoires) | P2 | 🔲 |
| P5.2.3 | Bandeau conformité RGPD | P1 | ✅ |
| P5.3.1 | Celery + Redis (tâches longues) | P2 | 🔲 |
| P5.3.2 | Monitoring quotas API | P2 | 🔲 |

**Légende** : ✅ fait · 🔶 partiel · 🔲 à faire

---

## Architecture cible

```
osint-ultimate/
├── app.py                 # App factory, scans, worker
├── config.py
├── models.py              # User, Scan, Entity, EntityLink
├── extensions.py
├── connectors/            # sherlock, hunter, …
├── services/              # détection, corrélation, express
├── routes/                # views, api_v1
├── templates/             # express, expert, base
├── migrations/
└── static/js/             # graph.js
```

---

## Secrets Hugging Face (référence complète)

Voir `SECRETS.md` pour la liste à jour.

---

## Jalons recommandés

| Jalon | Contenu | Cible |
|-------|---------|-------|
| **M1** | Express + Expert + Sherlock + PDF | ✅ V4.1 |
| **M2** | Corrélation + graphe + API v1 | ✅ V4.2 |
| **M3** | Hunter + Dehashed + CSV | V5.0 |
| **M4** | Celery + scans programmés | V5.1 |
| **M5** | Marketplace connecteurs | V6 |

---

*Dernière mise à jour : mai 2026 — maintenir ce fichier à chaque release.*
