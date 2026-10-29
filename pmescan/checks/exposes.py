"""Vérification des fichiers et répertoires sensibles exposés (mode actif).

Ce check est intrusif : il demande explicitement des chemins sensibles sur le
serveur cible. Il ne s'active donc qu'à partir du mode « actif ».
"""

import re
import secrets
from collections.abc import Callable
from dataclasses import dataclass

import httpx

from pmescan.checks.base import Verification
from pmescan.modele import Cible, Gravite, Resultat
from pmescan.reseau import client_garde

# Taille maximale lue par réponse : un vrai « backup.zip » peut peser des gigaoctets, et
# les validateurs n'ont besoin que du début du fichier.
_TAILLE_MAX = 64 * 1024

# Chemin témoin, inexistant par construction (suffixe aléatoire ajouté à chaque scan). Sa
# réponse montre comment le serveur répond à une adresse qui n'existe pas.
_PREFIXE_TEMOIN = "/pmescan-inexistant-"

# Contenu d'un fichier .git/HEAD : référence de branche, ou empreinte SHA-1 / SHA-256.
_MOTIF_HEAD_GIT = re.compile(r"ref: refs/\S+|[0-9a-f]{40}|[0-9a-f]{64}")

# Motif d'une ligne de fichier .env : CLE_EN_MAJUSCULES=valeur.
_MOTIF_ENV = re.compile(r"(?m)^[A-Z][A-Z0-9_]*=")

# Titre d'une page phpinfo() : « <title>PHP 8.2.1 - phpinfo()</title> ».
_MOTIF_PHPINFO = re.compile(r"<title>[^<]*phpinfo\(\)[^<]*</title>", re.IGNORECASE)

# Titre ou en-tête d'un listing automatique : « Index of / ».
_MOTIF_LISTING = re.compile(r"<(title|h1)>\s*Index of /", re.IGNORECASE)

# Signatures d'une archive ZIP : en-tête de fichier local, ou archive vide.
_SIGNATURES_ZIP = (b"PK\x03\x04", b"PK\x05\x06")


@dataclass(frozen=True)
class _Page:
    """Début d'une réponse HTTP : seuls les premiers octets du corps sont conservés."""

    statut: int
    type_contenu: str
    corps: bytes
    chemin_final: str      # chemin après redirections
    encodage: str

    @property
    def texte(self) -> str:
        return self.corps.decode(self.encodage, errors="replace")

    @property
    def est_html(self) -> bool:
        return "text/html" in self.type_contenu or self.texte.lstrip().startswith("<")


def _est_depot_git(page: _Page) -> bool:
    """Vrai si la page est le fichier /.git/HEAD d'un dépôt Git exposé."""
    return page.statut == 200 and _MOTIF_HEAD_GIT.fullmatch(page.texte.strip()) is not None


def _est_fichier_env(page: _Page) -> bool:
    """Vrai si la page est un fichier .env (variables d'environnement), pas une page HTML."""
    return page.statut == 200 and not page.est_html and bool(_MOTIF_ENV.search(page.texte))


def _est_archive(page: _Page) -> bool:
    """Vrai si la page commence par la signature d'une archive ZIP.

    Le type annoncé (Content-Type) ne suffit pas : seuls les octets du fichier comptent.
    """
    return page.statut == 200 and page.corps[:4] in _SIGNATURES_ZIP


def _est_phpinfo(page: _Page) -> bool:
    """Vrai si la page est une page phpinfo() divulguant la configuration PHP."""
    return page.statut == 200 and bool(_MOTIF_PHPINFO.search(page.texte))


def _est_listing_repertoire(page: _Page) -> bool:
    """Vrai si la page est un listing de répertoire automatique du serveur."""
    return page.statut == 200 and bool(_MOTIF_LISTING.search(page.texte))


# Chemins sensibles testés : (chemin, identifiant, gravité, validateur du contenu).
_CIBLES: tuple[tuple[str, str, Gravite, Callable[[_Page], bool]], ...] = (
    ("/.git/HEAD", "fichier_expose_git", Gravite.CRITIQUE, _est_depot_git),
    ("/.env", "fichier_expose_env", Gravite.CRITIQUE, _est_fichier_env),
    ("/backup.zip", "fichier_expose_backup", Gravite.ELEVEE, _est_archive),
    ("/phpinfo.php", "fichier_expose_phpinfo", Gravite.ELEVEE, _est_phpinfo),
    ("/", "fichier_expose_listing", Gravite.ELEVEE, _est_listing_repertoire),
)


async def _lire(client: httpx.AsyncClient, url: str) -> _Page | None:
    """Lit le début de la réponse à ``url`` (au plus _TAILLE_MAX octets), sinon None."""
    try:
        async with client.stream("GET", url) as reponse:
            corps = bytearray()
            async for morceau in reponse.aiter_bytes():
                corps.extend(morceau)
                if len(corps) >= _TAILLE_MAX:
                    break
            return _Page(
                statut=reponse.status_code,
                type_contenu=reponse.headers.get("content-type", "").lower(),
                corps=bytes(corps[:_TAILLE_MAX]),
                chemin_final=reponse.url.path,
                encodage=reponse.charset_encoding or "utf-8",
            )
    except (httpx.HTTPError, LookupError):
        # Erreur réseau, ou jeu de caractères inconnu annoncé par le serveur.
        return None


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
            temoin = await _lire(
                client, f"https://{cible.domaine}{_PREFIXE_TEMOIN}{secrets.token_hex(8)}"
            )
            for chemin, identifiant, gravite, validateur in _CIBLES:
                resultat = await self._tester(
                    client, cible, chemin, identifiant, gravite, validateur, temoin
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
        validateur: Callable[[_Page], bool],
        temoin: _Page | None,
    ) -> Resultat | None:
        """Teste un chemin et renvoie un Resultat s'il est exposé, sinon None.

        Une réponse 200 ne suffit pas. Le chemin n'est exposé que si :
        - le contenu ressemble vraiment au fichier attendu (validateur) ;
        - la réponse vient bien de ce chemin, pas d'une redirection vers l'accueil ou
          une page de connexion ;
        - le serveur ne répond pas la même chose à une adresse inexistante (témoin) :
          certains sites renvoient 200 et la même page pour n'importe quelle adresse.
        """
        url = f"https://{cible.domaine}{chemin}"
        page = await _lire(client, url)
        if page is None or not validateur(page):
            return None
        if page.chemin_final != chemin:
            return None
        if temoin is not None and (validateur(temoin) or temoin.corps == page.corps):
            return None
        return Resultat(
            identifiant=identifiant,
            gravite=gravite,
            reussi=False,
            preuve=url,
            details={"url": url},
        )
