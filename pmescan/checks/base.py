"""Contrat commun à toutes les vérifications de sécurité."""

from abc import ABC, abstractmethod

from pmescan.modele import Cible, Resultat


class Verification(ABC):
    """Classe mère de toutes les vérifications.

    Chaque vérification fait une seule chose : analyser la cible et renvoyer une
    liste de ``Resultat``. Elle ne connaît ni la notation ni le rapport.
    """

    nom: str = "verification"
    niveau_minimum: str = "passif"   # mode minimal qui active ce check

    @abstractmethod
    async def executer(self, cible: Cible) -> list[Resultat]:
        """Analyse la cible et renvoie la liste des problèmes trouvés."""
        ...
