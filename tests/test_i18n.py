"""Tests du chargement des textes vulgarisés (i18n) et de leur cohérence avec le code.

Objectif (item 2 du réviseur) : garantir, de façon EXHAUSTIVE et DÉRIVÉE DU CODE, que
chaque identifiant de problème (résultat non réussi) réellement émis par une vérification
possède une entrée complète dans fr.yaml.

Méthode retenue : plutôt qu'une liste d'identifiants recopiée à la main (qui se périme
en silence), on exécute chaque vérification de ``pmescan.scanner.VERIFICATIONS`` contre
des scénarios mockés hors-ligne qui forcent les cas « problème », puis on collecte les
``identifiant`` des ``Resultat`` avec ``reussi=False``. Ainsi, si un développeur ajoute
un check (ou un nouveau cas d'échec) sans le texte associé dans fr.yaml, ce test échoue
sans qu'on ait à éditer la moindre liste manuelle.

Tout est mocké (sslyze, httpx via respx, dnspython) : aucun accès réseau.
"""

import asyncio
import unittest.mock as mock

import dns.asyncresolver
import dns.exception
import dns.resolver
import httpx
import pytest
import respx

import pmescan.checks.tls as tls_module
from pmescan.checks.cms import VerificationCms
from pmescan.checks.dns_mail import VerificationDnsMail
from pmescan.checks.entetes import VerificationEntetes
from pmescan.checks.exposes import VerificationFichiersExposes
from pmescan.checks.ports import _PORTS, VerificationPorts
from pmescan.checks.tls import VerificationTls
from pmescan.i18n import charger_textes
from pmescan.modele import Cible
from pmescan.scanner import VERIFICATIONS
from tests.conftest import (
    FauxChiffrement,
    FauxChiffrementAccepte,
    FauxResultatChiffrements,
    charger_fixture,
    construire_rapport,
    construire_scan_result,
    faux_open_connection,
    faux_resoudre,
    tentative_chiffrements,
)

# Clés obligatoires de chaque entrée de texte, et responsables autorisés.
_CLES_ATTENDUES = {"titre", "risque", "qui_corrige", "effort", "action"}
_RESPONSABLES_VALIDES = {"hebergeur", "developpeur", "gerant"}

# Cible commune aux scénarios : mode « actif » pour activer aussi les checks intrusifs.
_CIBLE = Cible(domaine="exemple.com", mode="actif")


# --- Outils de mock partagés -------------------------------------------------


def _reponse_depuis_fixture(nom: str) -> httpx.Response:
    """Fabrique une réponse httpx à partir d'une fixture enregistrée (en-têtes + cookies)."""
    donnees = charger_fixture(nom)
    entetes = list(donnees["entetes"].items())
    for cookie in donnees.get("cookies", []):
        entetes.append(("set-cookie", cookie))
    return httpx.Response(donnees["statut"], headers=entetes)


def _faux_resolver(reponses: dict):
    """Fausse coroutine ``dns.asyncresolver.resolve`` pilotée par ``reponses``.

    Une clé ``(nom, type)`` absente retombe sur NoAnswer (enregistrement absent mais
    domaine existant). Une valeur exception est levée ; sinon on renvoie les textes.
    """

    async def _resolve(nom, type_enreg, *args, **kwargs):
        valeur = reponses.get((nom, type_enreg), dns.resolver.NoAnswer)
        if isinstance(valeur, type) and issubclass(valeur, BaseException):
            raise valeur()
        return [mock.Mock(to_text=lambda t=texte: t) for texte in valeur]

    return _resolve


# --- Scénarios « problème » par vérification ---------------------------------
# Chaque fonction renvoie une liste de listes de Resultat (une par scénario mocké).
# Les scénarios sont choisis pour déclencher TOUS les cas d'échec de chaque check.


def _resultats_tls() -> list[list]:
    verif = VerificationTls()
    resultats: list[list] = []

    # 1) sslyze lève une exception -> tls_erreur_connexion.
    with mock.patch.object(VerificationTls, "_scanner_sslyze", side_effect=OSError("injoignable")):
        resultats.append(asyncio.run(verif.executer(_CIBLE)))

    # 2) scan non terminé (pas de connectivité) -> tls_injoignable.
    rapport_vide = construire_rapport(None)
    with mock.patch.object(VerificationTls, "_scanner_sslyze", return_value=rapport_vide):
        resultats.append(asyncio.run(verif.executer(_CIBLE)))

    # 3-5) scans terminés avec problèmes. On patche CipherSuitesScanResult pour que les
    # isinstance() du code acceptent nos faux résultats, et on force une redirection absente.
    with (
        mock.patch.object(tls_module, "CipherSuitesScanResult", FauxResultatChiffrements),
        respx.mock(assert_all_called=False) as routeur,
    ):
        routeur.get("http://exemple.com/").mock(return_value=httpx.Response(200))

        # 3) certificat expiré -> tls_expire (+ redirection absente).
        rapport = construire_rapport(construire_scan_result(jours_avant_expiration=-5))
        with mock.patch.object(VerificationTls, "_scanner_sslyze", return_value=rapport):
            resultats.append(asyncio.run(verif.executer(_CIBLE)))

        # 4) certificat proche de l'expiration -> tls_expiration_proche.
        rapport = construire_rapport(construire_scan_result(jours_avant_expiration=10))
        with mock.patch.object(VerificationTls, "_scanner_sslyze", return_value=rapport):
            resultats.append(asyncio.run(verif.executer(_CIBLE)))

        # 5) TLS 1.0 accepté avec RC4 -> tls_protocole_obsolete + tls_chiffrement_faible.
        faible = FauxChiffrementAccepte(FauxChiffrement("TLS_RSA_WITH_RC4_128_SHA", key_size=128))
        scan = construire_scan_result(tls_1_0=tentative_chiffrements([faible]))
        rapport_faible = construire_rapport(scan)
        with mock.patch.object(VerificationTls, "_scanner_sslyze", return_value=rapport_faible):
            resultats.append(asyncio.run(verif.executer(_CIBLE)))

    return resultats


def _resultats_entetes() -> list[list]:
    verif = VerificationEntetes()
    resultats: list[list] = []

    # 1) réponse sans aucun en-tête de sécurité, cookie non protégé, version divulguée.
    with respx.mock(assert_all_called=False) as routeur:
        routeur.get("https://exemple.com/").mock(
            return_value=_reponse_depuis_fixture("entetes_non_securises.json")
        )
        resultats.append(asyncio.run(verif.executer(_CIBLE)))

    # 2) hôte injoignable -> entetes_injoignable.
    with respx.mock(assert_all_called=False) as routeur:
        routeur.get("https://exemple.com/").mock(side_effect=httpx.ConnectError("refus"))
        resultats.append(asyncio.run(verif.executer(_CIBLE)))

    return resultats


def _resultats_dns_mail() -> list[list]:
    verif = VerificationDnsMail()
    resultats: list[list] = []

    # 1) domaine résolvable mais tout absent -> mx/spf/dmarc/dkim/dnssec absents.
    with mock.patch.object(dns.asyncresolver, "resolve", _faux_resolver({})):
        resultats.append(asyncio.run(verif.executer(_CIBLE)))

    # 2) délai dépassé sur la requête MX -> dns_erreur.
    with mock.patch.object(
        dns.asyncresolver, "resolve", _faux_resolver({("exemple.com", "MX"): dns.exception.Timeout})
    ):
        resultats.append(asyncio.run(verif.executer(_CIBLE)))

    # 3) NXDOMAIN sur la requête MX -> dns_domaine_introuvable.
    with mock.patch.object(
        dns.asyncresolver, "resolve", _faux_resolver({("exemple.com", "MX"): dns.resolver.NXDOMAIN})
    ):
        resultats.append(asyncio.run(verif.executer(_CIBLE)))

    return resultats


def _resultats_exposes() -> list[list]:
    verif = VerificationFichiersExposes()
    # Chaque chemin sensible renvoie un contenu qui valide son détecteur -> tous exposés.
    with respx.mock(assert_all_called=False) as routeur:
        routeur.get("https://exemple.com/.git/HEAD").mock(
            return_value=httpx.Response(200, text="ref: refs/heads/main\n")
        )
        routeur.get("https://exemple.com/.env").mock(
            return_value=httpx.Response(200, text="SECRET_KEY=abc\nDB_PASSWORD=x\n")
        )
        routeur.get("https://exemple.com/backup.zip").mock(
            return_value=httpx.Response(
                200, headers={"content-type": "application/zip"}, content=b"PK\x03\x04"
            )
        )
        routeur.get("https://exemple.com/phpinfo.php").mock(
            return_value=httpx.Response(200, text="<title>phpinfo()</title>")
        )
        routeur.get("https://exemple.com/").mock(
            return_value=httpx.Response(200, text="<title>Index of /</title>")
        )
        return [asyncio.run(verif.executer(_CIBLE))]


def _resultats_cms() -> list[list]:
    verif = VerificationCms()
    # Mode ACTIF (sonde des chemins et vérifications WordPress) et OSV activé : sans
    # verifier_cve=True, cms_vulnerable et cms_cve_indeterminee ne sont jamais émis.
    cible = Cible(domaine="exemple.com", mode="actif", verifier_cve=True)
    base = "https://exemple.com"
    url_osv = "https://api.osv.dev/v1/query"

    def _accueil(routeur, generateur: str) -> None:
        routeur.get(f"{base}/").mock(
            return_value=httpx.Response(
                200, text=f'<meta name="generator" content="{generateur}" />'
            )
        )

    resultats: list[list] = []

    # 1) WordPress 5.0 en mode actif -> cms_obsolete, wp_xmlrpc_actif,
    #    wp_enumeration_utilisateurs (+ cms_cve_indeterminee : WordPress non couvert par OSV).
    with respx.mock(assert_all_called=False) as routeur:
        routeur.get(f"{base}/xmlrpc.php").mock(
            return_value=httpx.Response(405, text="XML-RPC server accepts POST requests only.")
        )
        # Route « /?author=1 » AVANT la page d'accueil : la première route qui
        # correspond gagne, et « / » sans paramètre accepterait aussi la requête.
        routeur.get(url=f"{base}/", params={"author": "1"}).mock(
            return_value=httpx.Response(301, headers={"location": f"{base}/author/admin/"})
        )
        routeur.get(f"{base}/author/admin/").mock(return_value=httpx.Response(200))
        _accueil(routeur, "WordPress 5.0")
        resultats.append(asyncio.run(verif.executer(cible)))

    # 2) Drupal 10.1 + OSV connaît des failles -> cms_vulnerable.
    with respx.mock(assert_all_called=False) as routeur:
        _accueil(routeur, "Drupal 10.1")
        routeur.post(url_osv).mock(
            return_value=httpx.Response(200, json={"vulns": [{"id": "CVE-2024-0001"}]})
        )
        resultats.append(asyncio.run(verif.executer(cible)))

    # 3) Drupal 10.1 + OSV injoignable -> cms_cve_indeterminee.
    with respx.mock(assert_all_called=False) as routeur:
        _accueil(routeur, "Drupal 10.1")
        routeur.post(url_osv).mock(side_effect=httpx.ConnectError("osv injoignable"))
        resultats.append(asyncio.run(verif.executer(cible)))

    return resultats


def _resultats_ports() -> list[list]:
    verif = VerificationPorts()
    resultats: list[list] = []

    # 1) Tous les ports surveillés « ouverts » -> chaque port_ouvert_* est émis. La
    #    résolution est remplacée par une IP factice : aucune requête DNS réelle.
    tous_les_ports = {port for port, _, _ in _PORTS}
    with (
        mock.patch.object(VerificationPorts, "_resoudre", faux_resoudre()),
        mock.patch.object(asyncio, "open_connection", faux_open_connection(tous_les_ports)),
    ):
        resultats.append(asyncio.run(verif.executer(_CIBLE)))

    # 2) Nom d'hôte introuvable -> ports_hote_introuvable.
    with mock.patch.object(VerificationPorts, "_resoudre", faux_resoudre(None)):
        resultats.append(asyncio.run(verif.executer(_CIBLE)))

    return resultats


# Association vérification -> fonction de scénarios. Clé = attribut ``nom`` du check.
_SCENARIOS_PAR_NOM = {
    "tls": _resultats_tls,
    "entetes": _resultats_entetes,
    "dns_mail": _resultats_dns_mail,
    "exposes": _resultats_exposes,
    "cms": _resultats_cms,
    "ports": _resultats_ports,
}


def _collecter_identifiants_non_reussis() -> set[str]:
    """Exécute tous les scénarios et renvoie les identifiants réellement émis en échec.

    On refuse de rester muet si un check de ``VERIFICATIONS`` n'a pas de scénario :
    ajouter un nouveau check impose donc d'écrire son scénario « problème » ici, ce qui
    garde le test exhaustif par construction.
    """
    noms_checks = {verif.nom for verif in VERIFICATIONS}
    sans_scenario = noms_checks - set(_SCENARIOS_PAR_NOM)
    if sans_scenario:
        raise RuntimeError(
            f"Scénario « problème » manquant pour les vérifications : {sorted(sans_scenario)}. "
            "Ajoutez-le dans tests/test_i18n.py pour garder la collecte exhaustive."
        )

    identifiants: set[str] = set()
    for nom in sorted(noms_checks):
        for liste in _SCENARIOS_PAR_NOM[nom]():
            identifiants.update(r.identifiant for r in liste if not r.reussi)

    # Les identifiants de repli f"{nom}_erreur_interne" sont produits par scanner.py quand
    # une vérification lève. Ce sont des diagnostics TECHNIQUES (hors périmètre i18n métier) :
    # on les exclut explicitement du contrôle des textes vulgarisés.
    return {ident for ident in identifiants if not ident.endswith("_erreur_interne")}


# Collecte faite une seule fois à l'import pour alimenter la paramétrisation.
_IDENTIFIANTS_NON_REUSSIS = sorted(_collecter_identifiants_non_reussis())


# --- Tests -------------------------------------------------------------------


def test_charger_textes_renvoie_un_dict():
    """charger_textes('fr') renvoie un dictionnaire non vide."""
    textes = charger_textes("fr")
    assert isinstance(textes, dict)
    assert textes


def test_la_collecte_couvre_chaque_check():
    """Garde-fou : la collecte dynamique a bien produit des échecs pour chaque check.

    Évite qu'un scénario cassé ne rende les tests paramétrés vides (donc vrais à vide).
    On vérifie la présence d'au moins un identifiant représentatif par vérification.
    """
    attendus_representatifs = {
        "tls_expire",
        "entete_hsts_absent",
        "mx_absent",
        "dns_domaine_introuvable",
        "fichier_expose_git",
        "cms_obsolete",
        "cms_vulnerable",
        "cms_cve_indeterminee",
        "wp_xmlrpc_actif",
        "wp_enumeration_utilisateurs",
        "port_ouvert_mysql",
        "port_ouvert_web_3000",
        "ports_hote_introuvable",
    }
    manquants = attendus_representatifs - set(_IDENTIFIANTS_NON_REUSSIS)
    assert not manquants, f"Scénarios à revoir, identifiants non collectés : {manquants}"


@pytest.mark.parametrize("identifiant", _IDENTIFIANTS_NON_REUSSIS)
def test_chaque_identifiant_a_un_texte_complet(identifiant):
    """Chaque identifiant non réussi émis possède une entrée fr.yaml avec toutes les clés."""
    textes = charger_textes("fr")
    assert identifiant in textes, f"Texte manquant dans fr.yaml pour « {identifiant} »"
    entree = textes[identifiant]
    assert isinstance(entree, dict), f"L'entrée « {identifiant} » n'est pas un dictionnaire"
    manquantes = _CLES_ATTENDUES - set(entree)
    assert not manquantes, f"Clés manquantes pour « {identifiant} » : {manquantes}"
    for cle in _CLES_ATTENDUES:
        valeur = entree[cle]
        assert isinstance(valeur, str) and valeur.strip(), (
            f"Champ « {cle} » vide pour « {identifiant} »"
        )


@pytest.mark.parametrize("identifiant", _IDENTIFIANTS_NON_REUSSIS)
def test_qui_corrige_est_un_responsable_connu(identifiant):
    """Le champ qui_corrige ne prend qu'une valeur parmi hebergeur/developpeur/gerant."""
    entree = charger_textes("fr")[identifiant]
    assert entree["qui_corrige"] in _RESPONSABLES_VALIDES


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
