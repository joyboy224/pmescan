"""Chargement des textes vulgarisés (i18n) associés à chaque identifiant de problème."""

import importlib.resources
from typing import Any

import yaml


def charger_textes(langue: str = "fr") -> dict[str, Any]:
    """Charge et renvoie les textes humains pour la langue demandée.

    Le fichier ``<langue>.yaml`` est lu depuis le paquet ``pmescan.i18n``. Chaque
    clé est un identifiant de problème (ex. ``dmarc_absent``) et chaque valeur un
    dictionnaire ``titre``/``risque``/``qui_corrige``/``effort``/``action``.
    """
    ressource = importlib.resources.files("pmescan.i18n") / f"{langue}.yaml"
    contenu = ressource.read_text(encoding="utf-8")
    donnees = yaml.safe_load(contenu)
    return donnees if isinstance(donnees, dict) else {}
