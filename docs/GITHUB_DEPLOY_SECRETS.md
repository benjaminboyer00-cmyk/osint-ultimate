# Secrets GitHub pour CI/CD VPS

Configurer dans **Settings → Secrets and variables → Actions** :

| Secret | Exemple | Usage |
|--------|---------|--------|
| `VPS_HOST` | `203.0.113.10` | IP ou hostname du VPS |
| `VPS_USER` | `deploy` | Utilisateur SSH |
| `VPS_SSH_KEY` | clé privée PEM | `ssh-keygen -t ed25519` |
| `VPS_APP_DIR` | `/opt/osint-ultimate` | Répertoire du projet sur le VPS |

## Premier déploiement sur le VPS

```bash
# Sur le VPS
sudo mkdir -p /opt/osint-ultimate
sudo chown deploy:deploy /opt/osint-ultimate
git clone https://github.com/VOTRE_ORG/osint-ultimate.git /opt/osint-ultimate
cd /opt/osint-ultimate
cp .env.example .env   # éditer avec les vraies valeurs
chmod +x scripts/deploy.sh scripts/backup.sh

# Login registry GitHub
echo $GITHUB_TOKEN | docker login ghcr.io -u USER --password-stdin

# Nginx
sudo cp deploy/nginx.conf /etc/nginx/sites-available/osint-ultimate
# Éditer server_name + chemins SSL
sudo ln -s /etc/nginx/sites-available/osint-ultimate /etc/nginx/sites-enabled/
sudo certbot --nginx -d votredomaine.io
```

## Déclencher un déploiement

Push sur `main` → workflow `Build & deploy VPS`.

Test manuel : **Actions → Build & deploy VPS → Run workflow**.

## Sentry (HF + VPS)

Ajouter dans les secrets du Space HF et dans `.env` VPS :

```
SENTRY_DSN=https://xxx@o0.ingest.sentry.io/0
SENTRY_ENVIRONMENT=production
```

Provocation test : route `/health` ne suffit pas — provoquer une 500 en staging puis vérifier le dashboard Sentry.
