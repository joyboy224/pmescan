"""Orchestration des vérifications selon le mode de la cible."""

import asyncio

from pmescan.checks.base import Verification
from pmescan.checks.cms import VerificationCms
from pmescan.checks.dns_mail import VerificationDnsMail
from pmescan.checks.entetes import VerificationEntetes
from pmescan.checks.exposes import VerificationFichiersExposes
from pmescan.checks.ports import VerificationPorts
from pmescan.checks.tls import VerificationTls
from pmescan.modele import Cible, Gravite, Resultat

# Ordre croissant d'intrusivité des modes.
_ORDRE_MODES: dict[str, int] = {"passif": 0, "actif": 1, "agressif": 2}

# Liste des vérifications disponibles, instanciées une fois.
VERIFICATIONS: list[Verification] = [
    VerificationTls(),
    VerificationEntetes(),
    VerificationDnsMail(),
    VerificationCms(),
    VerificationFichiersExposes(),
    VerificationPorts(),
]


def _mode_compatible(niveau_minimum: str, mode: str) -> bool:
    """Vrai si une vérification de ce niveau peut s'exécuter dans ce mode."""
    return _ORDRE_MODES.get(niveau_minimum, 0) <= _ORDRE_MODES.get(mode, 0)


def _est_intrusive(verification: Verification) -> bool:
    """Vrai si la vérification exige au moins le mode actif."""
    return _ORDRE_MODES.get(verification.niveau_minimum, 0) > _ORDRE_MODES["passif"]


def selectionner_verifications(
    mode: str, autorisation: bool = False
) -> list[Verification]:
    """Renvoie les vérifications activées pour le mode demandé.

    Défense en profondeur : une vérification intrusive (niveau actif ou agressif) n'est
    retenue que si ``autorisation`` est vrai, même si ``mode`` la permet. Sans
    autorisation, elle est ignorée silencieusement, comme en mode passif. Ainsi l'API
    Python ne lance jamais de requête intrusive sans autorisation explicite, même si un
    appelant construit une Cible en mode « actif » sans passer par la garde de la CLI.
    """
    return [
        v
        for v in VERIFICATIONS
        if _mode_compatible(v.niveau_minimum, mode)
        and (autorisation or not _est_intrusive(v))
    ]


async def scanner(cible: Cible) -> list[Resultat]:
    """Exécute en parallèle les vérifications compatibles et agrège les résultats."""
    verifications = selectionner_verifications(cible.mode, cible.autorisation)
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
