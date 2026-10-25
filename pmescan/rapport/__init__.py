"""Génération du rapport de sécurité en français (HTML pur, puis PDF natif)."""

from pmescan.rapport.generateur import construire_contexte, ecrire_pdf, rendre_html

__all__ = ["construire_contexte", "ecrire_pdf", "rendre_html"]
