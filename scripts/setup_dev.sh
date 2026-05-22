#!/bin/bash
# Environnement local pour flask / pytest (évite ModuleNotFoundError: whois)
set -e
cd "$(dirname "$0")/.."
python3 -m venv .venv
.venv/bin/pip install --upgrade pip
.venv/bin/pip install -r requirements.txt
echo ""
echo "✓ Environnement prêt. Utilisez :"
echo "  source .venv/bin/activate"
echo "  export FLASK_APP=app:app"
echo "  flask db upgrade"
echo "  python -m pytest tests/ -q"
