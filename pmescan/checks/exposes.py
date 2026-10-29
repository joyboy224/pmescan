"""Vérification des fichiers et répertoires sensibles exposés (mode actif).

Ce check est intrusif : il demande explicitement des chemins sensibles sur le
serveur cible. Il ne s'active donc qu'à partir du mode « actif ».
"""

import re
from collections.abc import Callable

import httpx

from pmescan.checks.base import Verification
from pmescan.modele import Cible, Gravite, Resultat
from pmescan.reseau import client_garde

# Motif d'une ligne de fichier .env : CLE_EN_MAJUSCULES=valeur.
_MOTIF_ENV = re.compile(r"(?m)^[A-Z][A-Z0-9_]*=")


def _est_depot_git(reponse: httpx.Response) -> bool:
    """Vrai si la réponse ressemble au fichier /.git/HEAD d'un dépôt Git exposé."""
    return reponse.status_code == 200 and reponse.text.lstrip().startswith("ref:")


def _est_fichier_env(reponse: httpx.Response) -> bool:
    """Vrai si la réponse ressemble à un fichier .env (variables d'environnement)."""
    if reponse.status_code != 200:
        return False
    return bool(_MOTIF_ENV.search(reponse.text))


def _est_archive(reponse: httpx.Response) -> bool:
    """Vrai si la réponse est une archive ZIP téléchargeable."""
    if reponse.status_code != 200:
        return False
    type_contenu = reponse.headers.get("content-type", "").lower()
    return "zip" in type_contenu or reponse.content[:2] == b"PK"


def _est_phpinfo(reponse: httpx.Response) -> bool:
    """Vrai si la réponse est une page phpinfo() divulguant la configuration PHP."""
    if reponse.status_code != 200:
        return False
    return "phpinfo()" in reponse.text or "PHP Version" in reponse.text


def _est_listing_repertoire(reponse: httpx.Response) -> bool:
    """Vrai si la réponse est un listing de répertoire automatique du serveur."""
    if reponse.status_code != 200:
        return False
    return "Index of /" in reponse.text or "<title>Index of" in reponse.text


# Chemins sensibles testés : (chemin, identifiant, gravité, validateur du contenu).
_CIBLES: tuple[tuple[str, str, Gravite, Callable[[httpx.Response], bool]], ...] = (
    ("/.git/HEAD", "fichier_expose_git", Gravite.CRITIQUE, _est_depot_git),
    ("/.env", "fichier_expose_env", Gravite.CRITIQUE, _est_fichier_env),
    ("/backup.zip", "fichier_expose_backup", Gravite.ELEVEE, _est_archive),
    ("/phpinfo.php", "fichier_expose_phpinfo", Gravite.ELEVEE, _est_phpinfo),
    ("/", "fichier_expose_listing", Gravite.ELEVEE, _est_listing_repertoire),
)


class VerificationFichiersExposes(Verification):
    """Teste la présence de fichiers et répertoires sensibles accessibles publiquement."""

    nom = "exposes"
    niveau_minimum = "actif"

    async def executer(self, cible: Cible) -> list[Resultat]:
        # Défense en profondeur : même appelé directement en Python, ce check intrusif
        # n'envoie aucune requête sans autorisation explicite.
        if not cible.autorisation:
            return []
        resultats: list[Resultat] = []
        # verify=False délibéré : la validité du certificat est traitée par le module
        # sslyze. Ce client httpx ne cherche que des fichiers exposés et ne doit pas
        # échouer sur un certificat invalide.
        # Garde réseau : adresses publiques et hôtes du site analysé seulement. Une
        # redirection ne peut pas entraîner ce check intrusif vers un site tiers.
        async with client_garde(
            cible.domaine, meme_site=True, follow_redirects=True, timeout=10.0, verify=False
        ) as client:
            for chemin, identifiant, gravite, validateur in _CIBLES:
                resultat = await self._tester(
                    client, cible, chemin, identifiant, gravite, validateur
                )
                if resultat is not None:
                    resultats.append(resultat)

        if not resultats:
            resultats.append(
                Resultat(identifiant="aucun_fichier_expose", gravite=Gravite.INFO, reussi=True)
            )
        return resultats

    async def _tester(
        self,
        client: httpx.AsyncClient,
        cible: Cible,
        chemin: str,
        identifiant: str,
        gravite: Gravite,
        validateur: Callable[[httpx.Response], bool],
    ) -> Resultat | None:
        """Teste un chemin et renvoie un Resultat s'il est exposé, sinon None."""
        url = f"https://{cible.domaine}{chemin}"
        try:
            reponse = await client.get(url)
        except httpx.HTTPError:
            # Erreur réseau sur ce chemin : on considère qu'il n'est pas exposé.
            return None
        if validateur(reponse):
            return Resultat(
                identifiant=identifiant,
                gravite=gravite,
                reussi=False,
                preuve=url,
                details={"url": url},
            )
        return None
