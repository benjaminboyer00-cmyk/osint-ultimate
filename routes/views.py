"""Agrégateur blueprint views — routes découpées par domaine."""
from routes.views_bp import views_bp, entities_paginated

# Enregistrement des routes (effet de bord à l'import)
from routes import lookup, pages, reports, entity, ops  # noqa: F401

__all__ = ['views_bp', 'entities_paginated']
