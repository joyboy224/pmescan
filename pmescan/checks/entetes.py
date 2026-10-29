"""Vérification des en-têtes HTTP de sécurité et des cookies via httpx."""

import re

import httpx

from pmescan.checks.base import Verification
from pmescan.modele import Cible, Gravite, Resultat
from pmescan.reseau import client_garde

# En-têtes de sécurité attendus : (nom HTTP, identifiant absent, identifiant présent, gravité).
_ENTETES_ATTENDUS: tuple[tuple[str, str, str, Gravite], ...] = (
    ("strict-transport-security", "entete_hsts_absent", "entete_hsts_present", Gravite.MOYENNE),
    ("content-security-policy", "entete_csp_absent", "entete_csp_present", Gravite.MOYENNE),
    (
        "x-frame-options",
        "entete_x_frame_options_absent",
        "entete_x_frame_options_present",
        Gravite.MOYENNE,
    ),
    (
        "x-content-type-options",
        "entete_x_content_type_options_absent",
        "entete_x_content_type_options_present",
        Gravite.FAIBLE,
    ),
    (
        "referrer-policy",
        "entete_referrer_policy_absent",
        "entete_referrer_policy_present",
        Gravite.FAIBLE,
    ),
    (
        "permissions-policy",
        "entete_permissions_policy_absent",
        "entete_permissions_policy_present",
        Gravite.FAIBLE,
    ),
)

# En-têtes susceptibles de divulguer une version logicielle.
# Cookies anti-CSRF des frameworks courants (Laravel, Angular, Django, Express/csurf) :
# le JavaScript du site doit les lire pour les renvoyer dans un en-tête. HttpOnly l'en
# empêcherait, son absence est donc normale. Secure et SameSite restent exigés.
_COOKIES_ANTI_CSRF = frozenset({"xsrf-token", "csrftoken", "csrf_token", "csrf-token", "_csrf"})

_ENTETES_VERSION = ("server", "x-powered-by")

# Un numéro de version ressemble à « 2.4.41 » ou « 7.4 ».
_MOTIF_VERSION = re.compile(r"\d+\.\d+")


class VerificationEntetes(Verification):
    """Analyse les en-têtes HTTP de sécurité et les attributs des cookies."""

    nom = "entetes"
    niveau_minimum = "passif"

    async def executer(self, cible: Cible) -> list[Resultat]:
        try:
            reponse = await self._recuperer_reponse(cible)
        except httpx.HTTPError as erreur:
            return [
                Resultat(
                    identifiant="entetes_injoignable",
                    gravite=Gravite.INFO,
                    reussi=False,
                    preuve=str(erreur),
                    details={"domaine": cible.domaine},
                )
            ]

        resultats: list[Resultat] = []
        resultats.extend(self._verifier_entetes_securite(reponse))
        resultats.extend(self._verifier_cookies(reponse))
        resultats.extend(self._verifier_fuite_version(reponse))
        return resultats

    async def _recuperer_reponse(self, cible: Cible) -> httpx.Response:
        """Récupère la réponse HTTPS en suivant les redirections."""
        url = f"https://{cible.domaine}/"
        # verify=False délibéré : la validité du certificat est traitée par le module
        # sslyze. Ce client httpx ne lit que les en-têtes et ne doit pas échouer sur
        # un certificat invalide.
        # Garde réseau : adresses publiques seulement, redirections comprises.
        async with client_garde(
            cible.domaine, meme_site=False, follow_redirects=True, timeout=10.0, verify=False
        ) as client:
            return await client.get(url)

    def _verifier_entetes_securite(self, reponse: httpx.Response) -> list[Resultat]:
        """Signale chaque en-tête de sécurité manquant."""
        resultats: list[Resultat] = []
        for nom_entete, identifiant_absent, identifiant_present, gravite in _ENTETES_ATTENDUS:
            valeur = reponse.headers.get(nom_entete)
            if valeur is None:
                resultats.append(
                    Resultat(
                        identifiant=identifiant_absent,
                        gravite=gravite,
                        reussi=False,
                        details={"entete": nom_entete},
                    )
                )
            else:
                resultats.append(
                    Resultat(
                        identifiant=identifiant_present,
                        gravite=Gravite.INFO,
                        reussi=True,
                        preuve=valeur,
                        details={"entete": nom_entete},
                    )
                )
        return resultats

    def _verifier_cookies(self, reponse: httpx.Response) -> list[Resultat]:
        """Vérifie les attributs Secure, HttpOnly et SameSite de chaque cookie."""
        resultats: list[Resultat] = []
        entetes_cookies = reponse.headers.get_list("set-cookie")
        for entete_cookie in entetes_cookies:
            segments = [segment.strip().lower() for segment in entete_cookie.split(";")]
            nom_cookie = entete_cookie.split("=", 1)[0].strip()
            attributs = set(segments[1:])
            manquants: list[str] = []
            if "secure" not in attributs:
                manquants.append("Secure")
            if "httponly" not in attributs and nom_cookie.lower() not in _COOKIES_ANTI_CSRF:
                manquants.append("HttpOnly")
            if not any(segment.startswith("samesite") for segment in attributs):
                manquants.append("SameSite")
            if manquants:
                resultats.append(
                    Resultat(
                        identifiant="cookie_non_securise",
                        gravite=Gravite.ELEVEE,
                        reussi=False,
                        preuve=nom_cookie,
                        details={"cookie": nom_cookie, "attributs_manquants": manquants},
                    )
                )
        if entetes_cookies and not resultats:
            resultats.append(
                Resultat(identifiant="cookies_securises", gravite=Gravite.INFO, reussi=True)
            )
        return resultats

    def _verifier_fuite_version(self, reponse: httpx.Response) -> list[Resultat]:
        """Signale les en-têtes qui divulguent une version logicielle précise."""
        resultats: list[Resultat] = []
        for nom_entete in _ENTETES_VERSION:
            valeur = reponse.headers.get(nom_entete)
            if valeur is None:
                continue
            if _MOTIF_VERSION.search(valeur) or nom_entete == "x-powered-by":
                resultats.append(
                    Resultat(
                        identifiant="entete_fuite_version",
                        gravite=Gravite.FAIBLE,
                        reussi=False,
                        preuve=f"{nom_entete}: {valeur}",
                        details={"entete": nom_entete, "valeur": valeur},
                    )
                )
        return resultats
