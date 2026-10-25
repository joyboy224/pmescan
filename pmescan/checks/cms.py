"""Détection de CMS (WordPress, Joomla, Drupal, PrestaShop) et de versions obsolètes.

Comportement selon le mode :

- **passif** (défaut) : on ne lit QUE la page d'accueil (meta generator, en-tête
  X-Generator, marqueurs techniques, cookies). Aucune autre URL de la cible n'est demandée.
- **actif** / **agressif** : on sonde en plus des fichiers de version connus (readme.html,
  CHANGELOG.txt, manifeste Joomla, /admin/) après une sonde « soft 404 », et on mène les
  vérifications propres à WordPress (xmlrpc.php, énumération des auteurs).

Le signal principal est la **branche majeure non maintenue** : on compare la branche
majeure détectée aux branches maintenues (table embarquée, meilleur effort).

En complément et de façon optionnelle (``--verifier-cve``), on interroge l'API publique
OSV pour savoir si la version détectée est touchée par des failles connues. Cette étape
est en meilleur effort : la couverture d'OSV sur les cœurs de CMS est partielle, et toute
indisponibilité réseau se dégrade proprement (aucun faux positif, aucune exception).
"""

import re
import uuid

import httpx

from pmescan.checks.base import Verification
from pmescan.modele import Cible, Gravite, Resultat

# Branches majeures encore maintenues (correctifs de sécurité) pour chaque CMS suivi.
# Table de meilleur effort, à vérifier sur les sites officiels, dernière mise à jour :
# 2026-10-25. Elle sert uniquement à repérer une branche manifestement abandonnée ; ce
# n'est pas une source d'autorité sur les correctifs de sécurité. Un simple retard de
# correctif à l'intérieur d'une branche maintenue n'est volontairement PAS signalé.
BRANCHES_MAINTENUES: dict[str, set[str]] = {
    # WordPress : 6.x (et 7.x dès sa sortie). Les branches 5.x et antérieures ne sont
    # plus la version recommandée par wordpress.org.
    "WordPress": {"6", "7"},
    # Joomla : 4.x en fin de vie depuis octobre 2025 ; 5.x et 6.x maintenues.
    "Joomla": {"5", "6"},
    # Drupal : 10.x (jusqu'à fin 2026) et 11.x ; 7.x en fin de vie depuis janvier 2025.
    "Drupal": {"10", "11"},
    # PrestaShop : 8.x et 9.x ; 1.7.x et antérieures en fin de vie.
    "PrestaShop": {"8", "9"},
}

# Correspondance CMS -> (écosystème, paquet) pour l'interrogation OSV. La couverture d'OSV
# sur les cœurs de CMS est partielle : une absence de réponse n'est donc pas une preuve
# d'absence de vulnérabilité. WordPress n'y figure pas : son cœur n'est pas indexé de
# façon fiable par OSV, on émet donc « cms_cve_indeterminee » plutôt qu'un faux « sain ».
_PAQUETS_OSV: dict[str, tuple[str, str]] = {
    "Drupal": ("Packagist", "drupal/core"),
    "PrestaShop": ("Packagist", "prestashop/prestashop"),
    "Joomla": ("Packagist", "joomla/joomla-cms"),
}

# Point d'accès public de l'API OSV (requête par version de paquet).
_URL_OSV = "https://api.osv.dev/v1/query"

# Délai maximal (secondes) de la requête OSV : un tiers lent ne doit pas bloquer le scan.
_DELAI_OSV = 5.0

# Modes autorisant la sonde de chemins et les vérifications propres à WordPress.
_MODES_SONDE = ("actif", "agressif")

# Balise <meta name="generator" content="..."> : source de CMS + version la plus fiable.
_MOTIF_GENERATOR = re.compile(
    r"""<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']""",
    re.IGNORECASE,
)

# Un numéro de version du style « 6.2 » ou « 10.1.4 ».
_MOTIF_VERSION = re.compile(r"\d+(?:\.\d+)+")

# Signature de readme.html WordPress : un <title> qui mentionne WordPress...
_MOTIF_TITRE_WORDPRESS = re.compile(r"<title>[^<]*wordpress[^<]*</title>", re.IGNORECASE)

# ... ET un marqueur propre à ce fichier : le logo <h1 id="logo"> ou un lien vers
# wordpress.org.
_MOTIF_MARQUEUR_README_WORDPRESS = re.compile(
    r"""<h1\s+id=["']logo["']|href=["']https?://(?:[a-z]+\.)?wordpress\.org""",
    re.IGNORECASE,
)

# Version affichée par readme.html : « <br /> Version X.Y » (et rien d'autre).
_MOTIF_VERSION_README_WORDPRESS = re.compile(r"<br\s*/?>\s*[Vv]ersion\s+(\d+(?:\.\d+)+)")

# CHANGELOG.txt de Drupal : le fichier COMMENCE par « Drupal X.Y » (après espaces).
_MOTIF_CHANGELOG_DRUPAL = re.compile(r"\s*Drupal\s+(\d+(?:\.\d+)+)")


def _extraire_version(texte: str) -> str | None:
    """Renvoie le premier numéro de version trouvé dans ``texte``, sinon None."""
    correspondance = _MOTIF_VERSION.search(texte)
    return correspondance.group(0) if correspondance else None


def _cms_depuis_libelle(libelle: str) -> str | None:
    """Associe un libellé libre (meta generator, en-tête) à un CMS connu."""
    libelle_bas = libelle.lower()
    if "wordpress" in libelle_bas:
        return "WordPress"
    if "joomla" in libelle_bas:
        return "Joomla"
    if "drupal" in libelle_bas:
        return "Drupal"
    if "prestashop" in libelle_bas:
        return "PrestaShop"
    return None


def _branche_non_maintenue(version: str, maintenues: set[str]) -> str | None:
    """Renvoie la branche majeure de ``version`` si elle n'est plus maintenue, sinon None.

    Une branche est jugée non maintenue seulement si elle est absente de ``maintenues``
    ET strictement inférieure à la plus petite branche maintenue : une branche plus récente
    que la table (table en retard) ne produit donc jamais de faux positif. En cas de format
    inattendu, on renvoie None.
    """
    majeure = version.split(".", 1)[0]
    try:
        numero = int(majeure)
        plus_petite = min(int(branche) for branche in maintenues)
    except ValueError:
        return None
    if majeure in maintenues or numero >= plus_petite:
        return None
    return majeure


class VerificationCms(Verification):
    """Détecte le CMS de la cible, repère une branche non maintenue et interroge OSV."""

    nom = "cms"
    niveau_minimum = "passif"

    async def executer(self, cible: Cible) -> list[Resultat]:
        resultats: list[Resultat] = []
        base = f"https://{cible.domaine}"
        sonde_autorisee = cible.mode in _MODES_SONDE
        # verify=False délibéré : la validité du certificat est traitée par le module
        # sslyze. Ce client httpx ne lit que des pages publiques de la CIBLE pour
        # identifier le CMS et ne doit pas échouer sur un certificat invalide. Il n'est
        # jamais utilisé pour parler à un tiers (OSV a son propre client, vérifié).
        async with httpx.AsyncClient(
            follow_redirects=True, timeout=10.0, verify=False
        ) as client:
            cms, version = await self._detecter(client, base, sonde_autorisee)
            if cms is None:
                return [
                    Resultat(
                        identifiant="cms_non_detecte",
                        gravite=Gravite.INFO,
                        reussi=True,
                        details={"domaine": cible.domaine},
                    )
                ]

            preuve = f"{cms} {version}" if version else cms
            resultats.append(
                Resultat(
                    identifiant="cms_detecte",
                    gravite=Gravite.INFO,
                    reussi=True,
                    preuve=preuve,
                    details={"cms": cms, "version": version},
                )
            )

            if version is not None:
                resultats.extend(await self._verifier_version(cible, cms, version))

            # xmlrpc.php et ?author=1 sollicitent d'autres URL que la page d'accueil :
            # réservés aux modes actif et agressif.
            if cms == "WordPress" and sonde_autorisee:
                resultats.extend(await self._verifier_wordpress(client, base))

        return resultats

    async def _verifier_version(
        self, cible: Cible, cms: str, version: str
    ) -> list[Resultat]:
        """Contrôle la branche de la version détectée et, en opt-in, les failles OSV."""
        resultats: list[Resultat] = []

        # OPT-IN : l'interrogation d'OSV envoie le nom et la version du CMS à un tiers
        # (api.osv.dev), jamais le domaine analysé. Pour respecter le principe « aucune
        # donnée envoyée à un tiers » de 03-CONCEPTION.md, on ne l'exécute que si la cible
        # a activé explicitement --verifier-cve.
        resultat_osv: Resultat | None = None
        if cible.verifier_cve:
            resultat_osv = await self._interroger_osv(cms, version)
            if resultat_osv is not None:
                resultats.append(resultat_osv)

        # Pas de double pénalité : si des failles connues sont confirmées
        # (cms_vulnerable, CRITIQUE), elles englobent l'obsolescence de la même version.
        # On n'émet alors pas cms_obsolete en plus, pour ne pas compter deux fois le même
        # problème dans la note.
        if resultat_osv is not None and resultat_osv.identifiant == "cms_vulnerable":
            return resultats

        maintenues = BRANCHES_MAINTENUES.get(cms)
        if maintenues:
            branche = _branche_non_maintenue(version, maintenues)
            if branche is not None:
                liste_maintenues = ", ".join(sorted(maintenues, key=int))
                resultats.append(
                    Resultat(
                        identifiant="cms_obsolete",
                        gravite=Gravite.ELEVEE,
                        reussi=False,
                        preuve=(
                            f"{cms} {version} : branche {branche}.x non maintenue "
                            f"(branches maintenues : {liste_maintenues})"
                        ),
                        details={
                            "cms": cms,
                            "version": version,
                            "branche": branche,
                            "branches_maintenues": sorted(maintenues, key=int),
                        },
                    )
                )
        return resultats

    async def _obtenir(
        self, client: httpx.AsyncClient, url: str
    ) -> httpx.Response | None:
        """Récupère une URL en meilleur effort ; renvoie None sur toute erreur réseau."""
        try:
            return await client.get(url)
        except httpx.HTTPError:
            return None

    async def _detecter(
        self, client: httpx.AsyncClient, base: str, sonde_autorisee: bool
    ) -> tuple[str | None, str | None]:
        """Identifie le CMS et sa version via la page d'accueil puis, si permis, des chemins."""
        accueil = await self._obtenir(client, f"{base}/")
        if accueil is not None:
            cms, version = self._detecter_depuis_reponse(accueil)
            if cms is not None:
                return cms, version

        # En mode passif, on s'arrête à la page d'accueil.
        if not sonde_autorisee:
            return None, None
        return await self._detecter_par_chemins(client, base)

    def _detecter_depuis_reponse(
        self, reponse: httpx.Response
    ) -> tuple[str | None, str | None]:
        """Déduit (CMS, version) d'une réponse : meta generator, en-têtes, puis corps."""
        # 1) Balise <meta name="generator"> : la plus fiable pour CMS + version.
        correspondance = _MOTIF_GENERATOR.search(reponse.text)
        if correspondance is not None:
            contenu = correspondance.group(1)
            cms = _cms_depuis_libelle(contenu)
            if cms is not None:
                return cms, _extraire_version(contenu)

        # 2) En-tête X-Generator (utilisé notamment par Drupal).
        entete_generator = reponse.headers.get("x-generator")
        if entete_generator is not None:
            cms = _cms_depuis_libelle(entete_generator)
            if cms is not None:
                return cms, _extraire_version(entete_generator)

        # 3) Marqueurs techniques dans le corps (sans numéro de version fiable). On évite
        # les mots-clés nus (« joomla », « prestashop ») qui apparaissent dans un simple
        # article de blog et produiraient des faux positifs.
        corps = reponse.text.lower()
        if "/wp-content/" in corps or "/wp-includes/" in corps:
            return "WordPress", None
        if "drupal.settings" in corps or "/sites/default/files" in corps:
            return "Drupal", None
        if "/media/jui/" in corps or "/media/system/js/" in corps or "option=com_" in corps:
            return "Joomla", None
        if "var prestashop =" in corps or "/modules/ps_" in corps:
            return "PrestaShop", None

        # 4) Cookie de session caractéristique de PrestaShop (nom « PrestaShop-<hash> »).
        for cookie in reponse.headers.get_list("set-cookie"):
            if cookie.lstrip().startswith("PrestaShop-"):
                return "PrestaShop", None
        return None, None

    def _reponse_ok(self, reponse: httpx.Response | None) -> httpx.Response | None:
        """Renvoie ``reponse`` si c'est un vrai 200, sinon None."""
        if reponse is None or reponse.status_code != 200:
            return None
        return reponse

    async def _detecter_par_chemins(
        self, client: httpx.AsyncClient, base: str
    ) -> tuple[str | None, str | None]:
        """Sonde des fichiers connus pour confirmer un CMS et en extraire la version.

        Avant toute sonde, on demande un chemin aléatoire qui ne peut pas exister. Si le
        site y répond 200 (« soft 404 » : page d'erreur ou d'accueil servie partout, au
        contenu parfois dynamique), aucun 200 n'est digne de confiance : on ne conclut
        rien des chemins. Chaque fichier doit en outre porter une signature qui lui est
        propre.
        """
        sonde = await self._obtenir(client, f"{base}/pmescan-{uuid.uuid4().hex}")
        if sonde is not None and sonde.status_code == 200:
            return None, None

        # WordPress : readme.html porte un <title> WordPress ET un marqueur propre au
        # fichier (logo ou lien wordpress.org) ; la version suit « <br /> Version ».
        reponse = self._reponse_ok(await self._obtenir(client, f"{base}/readme.html"))
        if (
            reponse is not None
            and _MOTIF_TITRE_WORDPRESS.search(reponse.text)
            and _MOTIF_MARQUEUR_README_WORDPRESS.search(reponse.text)
        ):
            correspondance = _MOTIF_VERSION_README_WORDPRESS.search(reponse.text)
            return "WordPress", (correspondance.group(1) if correspondance else None)

        # Drupal : CHANGELOG.txt COMMENCE par « Drupal X.Y, ... ».
        for chemin in ("/CHANGELOG.txt", "/core/CHANGELOG.txt"):
            reponse = self._reponse_ok(await self._obtenir(client, f"{base}{chemin}"))
            if reponse is not None:
                correspondance = _MOTIF_CHANGELOG_DRUPAL.match(reponse.text)
                if correspondance is not None:
                    return "Drupal", correspondance.group(1)

        # Joomla : manifeste XML <extension ...> exposant <version>X.Y.Z</version>.
        reponse = self._reponse_ok(
            await self._obtenir(client, f"{base}/administrator/manifests/files/joomla.xml")
        )
        if (
            reponse is not None
            and "<extension" in reponse.text
            and "joomla" in reponse.text.lower()
        ):
            correspondance = re.search(r"<version>\s*(\d+(?:\.\d+)+)\s*</version>", reponse.text)
            return "Joomla", (correspondance.group(1) if correspondance else None)

        # PrestaShop : page d'administration par défaut accessible.
        reponse = self._reponse_ok(await self._obtenir(client, f"{base}/admin/"))
        if reponse is not None and "prestashop" in reponse.text.lower():
            return "PrestaShop", None

        return None, None

    async def _interroger_osv(self, cms: str, version: str) -> Resultat | None:
        """Interroge OSV pour la version détectée (meilleur effort).

        Renvoie ``cms_vulnerable`` (CRITIQUE) si des failles identifiées sont connues,
        ``None`` si OSV ne connaît pas de faille, et ``cms_cve_indeterminee`` (INFO) si le
        CMS n'est pas couvert, si OSV est injoignable ou renvoie une réponse inexploitable.
        Aucune exception ne sort de cette méthode.
        """
        paquet = _PAQUETS_OSV.get(cms)
        if paquet is None:
            return self._cve_indeterminee(cms, version, "CMS non couvert par OSV")
        ecosysteme, nom_paquet = paquet
        corps = {
            "version": version,
            "package": {"name": nom_paquet, "ecosystem": ecosysteme},
        }
        # Client DÉDIÉ au tiers OSV : certificat vérifié (verify=True), aucune redirection
        # suivie et délai court. Il ne partage rien avec le client de la cible.
        try:
            async with httpx.AsyncClient(
                verify=True, follow_redirects=False, timeout=_DELAI_OSV
            ) as client_osv:
                reponse = await client_osv.post(_URL_OSV, json=corps)
        except httpx.HTTPError:
            return self._cve_indeterminee(cms, version, "OSV injoignable")

        if reponse.status_code != 200:
            return self._cve_indeterminee(cms, version, f"OSV a répondu {reponse.status_code}")

        try:
            donnees = reponse.json()
        except ValueError:
            return self._cve_indeterminee(cms, version, "réponse OSV illisible")

        vulnerabilites = donnees.get("vulns") if isinstance(donnees, dict) else None
        if not vulnerabilites:
            # OSV ne connaît aucune faille pour cette version (couverture partielle des
            # cœurs de CMS) : on n'émet rien plutôt qu'un faux « site sain ».
            return None
        if not isinstance(vulnerabilites, list):
            return self._cve_indeterminee(cms, version, "réponse OSV illisible")

        identifiants = [
            str(vuln.get("id"))
            for vuln in vulnerabilites
            if isinstance(vuln, dict) and vuln.get("id")
        ]
        if not identifiants:
            # Des entrées existent mais aucune n'est identifiable : on ne peut pas affirmer
            # une vulnérabilité précise.
            return self._cve_indeterminee(cms, version, "réponse OSV sans identifiant")

        apercu = ", ".join(identifiants[:5])
        return Resultat(
            identifiant="cms_vulnerable",
            gravite=Gravite.CRITIQUE,
            reussi=False,
            preuve=f"{cms} {version} : {len(identifiants)} faille(s) connue(s) ({apercu})",
            details={"cms": cms, "version": version, "cve": identifiants},
        )

    def _cve_indeterminee(self, cms: str, version: str, motif: str) -> Resultat:
        """Fabrique un résultat INFO signalant que l'état des failles n'a pas pu être établi."""
        return Resultat(
            identifiant="cms_cve_indeterminee",
            gravite=Gravite.INFO,
            reussi=False,
            preuve=f"{cms} {version} : {motif}",
            details={"cms": cms, "version": version, "motif": motif},
        )

    async def _verifier_wordpress(
        self, client: httpx.AsyncClient, base: str
    ) -> list[Resultat]:
        """Vérifications propres à WordPress : xmlrpc.php actif et énumération d'utilisateurs."""
        resultats: list[Resultat] = []

        # xmlrpc.php : en GET, un serveur actif répond « only POST requests ».
        reponse = await self._obtenir(client, f"{base}/xmlrpc.php")
        if reponse is not None and (
            reponse.status_code in (200, 405) and "xml-rpc" in reponse.text.lower()
        ):
            resultats.append(
                Resultat(
                    identifiant="wp_xmlrpc_actif",
                    gravite=Gravite.FAIBLE,
                    reussi=False,
                    preuve=f"{base}/xmlrpc.php",
                    details={"url": f"{base}/xmlrpc.php"},
                )
            )

        # Énumération d'utilisateurs : /?author=1 redirige vers /author/<identifiant>/, et
        # cette page finale doit exister (200), sinon la redirection ne prouve rien.
        reponse = await self._obtenir(client, f"{base}/?author=1")
        if (
            reponse is not None
            and reponse.status_code == 200
            and "/author/" in str(reponse.url)
        ):
            resultats.append(
                Resultat(
                    identifiant="wp_enumeration_utilisateurs",
                    gravite=Gravite.MOYENNE,
                    reussi=False,
                    preuve=str(reponse.url),
                    details={"url": str(reponse.url)},
                )
            )
        return resultats
