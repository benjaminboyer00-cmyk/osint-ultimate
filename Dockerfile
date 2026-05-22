FROM python:3.10-slim
# Définir le répertoire de travail
WORKDIR /code
# Installer les dépendances système nécessaires si besoin
RUN apt-get update && apt-get install -y --no-install-recommends \
build-essential \
&& rm -rf /var/lib/apt/lists/*
# Copier le fichier des modules requis
COPY requirements.txt .
# Installer les paquets Python
RUN pip install --no-cache-dir --upgrade pip && \
pip install --no-cache-dir -r requirements.txt
# Copier le reste du code de l'application
COPY . .
# Hugging Face Spaces utilise le port 7860 par défaut
EXPOSE 7860
# Lancement de l'application avec Gunicorn et Gevent pour les WebSockets
CMD ["gunicorn", "-k", "gevent", "-w", "1", "-b", "0.0.0.0:7860", "app:app"]
