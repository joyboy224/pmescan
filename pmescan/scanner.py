"""Orchestration des vérifications selon le mode de la cible."""

import asyncio

from pmescan.checks.base import Verification
from pmescan.checks.entetes import VerificationEntetes
from pmescan.checks.tls import VerificationTls
from pmescan.modele import Cible, Gravite, Resultat

# Ordre croissant d'intrusivité des modes.
_ORDRE_MODES: dict[str, int] = {"passif": 0, "actif": 1, "agressif": 2}

# Liste des vérifications disponibles, instanciées une fois.
VERIFICATIONS: list[Verification] = [
    VerificationTls(),
    VerificationEntetes(),
]


def _mode_compatible(niveau_minimum: str, mode: str) -> bool:
    """Vrai si une vérification de ce niveau peut s'exécuter dans ce mode."""
    return _ORDRE_MODES.get(niveau_minimum, 0) <= _ORDRE_MODES.get(mode, 0)


def selectionner_verifications(mode: str) -> list[Verification]:
    """Renvoie les vérifications activées pour le mode demandé."""
    return [v for v in VERIFICATIONS if _mode_compatible(v.niveau_minimum, mode)]


async def scanner(cible: Cible) -> list[Resultat]:
    """Exécute en parallèle les vérifications compatibles et agrège les résultats."""
    verifications = selectionner_verifications(cible.mode)
    taches = [verification.executer(cible) for verification in verifications]
    # return_exceptions=True : l'orchestrateur reste robuste même si un check lève.
    listes = await asyncio.gather(*taches, return_exceptions=True)
    resultats: list[Resultat] = []
    for verification, liste in zip(verifications, listes, strict=True):
        if isinstance(liste, BaseException):
            # Une vérification a échoué sans se rattraper : on la convertit en résultat.
            resultats.append(
                Resultat(
                    identifiant=f"{verification.nom}_erreur_interne",
                    gravite=Gravite.INFO,
                    reussi=False,
                    preuve=str(liste),
                    details={"verification": verification.nom},
                )
            )
        else:
            resultats.extend(liste)
    return resultats
