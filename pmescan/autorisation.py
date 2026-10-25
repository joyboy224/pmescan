"""Garde d'autorisation des modes intrusifs et journal local de consentement.

Les modes ``actif`` et ``agressif`` sollicitent activement la cible : ils ne doivent
s'exécuter que si l'utilisateur confirme être propriétaire de la cible ou disposer d'une
autorisation écrite (voir ``README-mode-agressif.md``). Chaque scan intrusif autorisé est
tracé localement dans ``~/.pmescan/consent.log``.
"""

import os
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path

# Variable d'environnement permettant de déplacer le dossier de pmescan (utile aux tests).
VARIABLE_DOSSIER = "PMESCAN_DOSSIER"

# Nom du fichier de journal de consentement, dans le dossier de pmescan.
NOM_JOURNAL = "consent.log"


class ModeScan(str, Enum):  # noqa: UP042 - même convention que Gravite (modele.py)
    """Modes de scan acceptés par la ligne de commande, du moins au plus intrusif."""

    PASSIF = "passif"
    ACTIF = "actif"
    AGRESSIF = "agressif"


# Modes qui sollicitent activement la cible et exigent une autorisation explicite.
MODES_INTRUSIFS: frozenset[ModeScan] = frozenset({ModeScan.ACTIF, ModeScan.AGRESSIF})


def exige_autorisation(mode: ModeScan) -> bool:
    """Vrai si le mode demandé exige le flag d'autorisation."""
    return mode in MODES_INTRUSIFS


def dossier_pmescan() -> Path:
    """Renvoie le dossier local de pmescan (``PMESCAN_DOSSIER`` ou ``~/.pmescan``)."""
    surcharge = os.environ.get(VARIABLE_DOSSIER)
    if surcharge:
        return Path(surcharge)
    return Path.home() / ".pmescan"


def _nettoyer_champ(valeur: str) -> str:
    """Remplace tout caractère non imprimable par une espace.

    Garde une ligne par entrée et un champ par colonne : couvre tabulations, retours à
    la ligne (\\r, \\n, \\x0b, \\x0c, \\x85, U+2028, U+2029) et le caractère
    d'échappement des séquences ANSI (\\x1b), qui pourraient falsifier l'affichage du
    journal dans un terminal.
    """
    return "".join(caractere if caractere.isprintable() else " " for caractere in valeur)


def journaliser_consentement(domaine: str, mode: ModeScan) -> Path:
    """Ajoute une ligne « horodatage UTC, domaine, mode » au journal de consentement.

    Le dossier est créé si besoin. Renvoie le chemin du journal. Lève ``OSError`` si
    l'écriture est impossible : l'appelant décide alors de la conduite à tenir.
    """
    dossier = dossier_pmescan()
    dossier.mkdir(parents=True, exist_ok=True)
    chemin = dossier / NOM_JOURNAL
    horodatage = datetime.now(UTC).isoformat(timespec="seconds")
    ligne = "\t".join([horodatage, _nettoyer_champ(domaine), mode.value])
    with chemin.open("a", encoding="utf-8") as journal:
        journal.write(ligne + "\n")
    return chemin
