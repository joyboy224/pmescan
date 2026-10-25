"""Tests hors-ligne de la vérification CMS (détection, branches, OSV, WordPress).

Toutes les réponses HTTP sont rejouées avec respx (fixture ``respx_mock``) : aucun accès
réseau réel. Toute requête non mockée lève une erreur respx, ce qui permet de prouver
qu'une URL n'est PAS demandée (mode passif notamment).

Rappels du comportement attendu :
- mode passif : seule la page d'accueil est lue ;
- mode actif : sonde « soft 404 », fichiers de version, puis xmlrpc.php et /?author=1
  pour WordPress ;
- OSV (api.osv.dev) est OPT-IN (``verifier_cve=True``) ; WordPress n'y est pas couvert.
"""

import asyncio
import json

import httpx
import pytest

import pmescan.checks.cms as cms_module
from pmescan.checks.cms import BRANCHES_MAINTENUES, VerificationCms, _branche_non_maintenue
from pmescan.modele import Cible, Gravite

DOMAINE = "exemple.com"
_BASE = f"https://{DOMAINE}"
_URL_OSV = "https://api.osv.dev/v1/query"
# Sonde soft 404 : /pmescan-<uuid4 hex> (32 caractères hexadécimaux).
_MOTIF_SONDE = r"https://exemple\.com/pmescan-[0-9a-f]{32}$"

# Certaines routes restent volontairement inutilisées (ex. OSV quand verifier_cve=False).
pytestmark = pytest.mark.respx(assert_all_called=False)


def _par_identifiant(resultats, identifiant):
    return next((r for r in resultats if r.identifiant == identifiant), None)


def _identifiants(resultats) -> set[str]:
    return {r.identifiant for r in resultats}


def _executer(mode: str = "passif", verifier_cve: bool = False):
    """Exécute la vérification CMS sur exemple.com."""
    cible = Cible(domaine=DOMAINE, mode=mode, verifier_cve=verifier_cve)
    return asyncio.run(VerificationCms().executer(cible))


def _generateur(contenu: str) -> str:
    """Page d'accueil minimale portant une balise meta generator."""
    return f'<html><head><meta name="generator" content="{contenu}" /></head></html>'


def _mocker_accueil(routeur, texte: str = "", headers=None) -> None:
    """Page d'accueil. À enregistrer APRÈS « /?author=1 » (la 1re route qui correspond gagne)."""
    routeur.get(f"{_BASE}/").mock(return_value=httpx.Response(200, text=texte, headers=headers))


def _mocker_wordpress_sain(routeur) -> None:
    """Sondes WordPress « rien à signaler » : xmlrpc.php en 404, /?author=1 sans redirection.

    La route « /?author=1 » est enregistrée ici, donc AVANT la page d'accueil : avec
    respx, une route « / » sans paramètre accepterait aussi « /?author=1 ».
    """
    routeur.get(f"{_BASE}/xmlrpc.php").mock(return_value=httpx.Response(404))
    routeur.get(url=f"{_BASE}/", params={"author": "1"}).mock(
        return_value=httpx.Response(200, text="page auteur")
    )


def _mocker_sonde_404(routeur) -> None:
    """La sonde soft 404 reçoit un vrai 404 : le site ne sert pas de page « fourre-tout »."""
    routeur.get(url__regex=_MOTIF_SONDE).mock(return_value=httpx.Response(404))


def _mocker_chemins_absents(routeur, sauf: tuple[str, ...] = ()) -> None:
    """Fait répondre 404 aux fichiers de version connus, sauf ceux de ``sauf``."""
    for chemin in (
        "/readme.html",
        "/CHANGELOG.txt",
        "/core/CHANGELOG.txt",
        "/administrator/manifests/files/joomla.xml",
        "/admin/",
    ):
        if chemin not in sauf:
            routeur.get(f"{_BASE}{chemin}").mock(return_value=httpx.Response(404))


# --- Détection du CMS (page d'accueil) ---------------------------------------


def test_cms_detecte_wordpress_via_meta_generator(respx_mock):
    """Un meta generator « WordPress 6.7.1 » produit cms_detecte réussi avec CMS + version."""
    _mocker_accueil(respx_mock, _generateur("WordPress 6.7.1"))

    resultats = _executer()

    detecte = _par_identifiant(resultats, "cms_detecte")
    assert detecte is not None
    assert detecte.reussi is True
    assert detecte.gravite is Gravite.INFO
    assert detecte.preuve == "WordPress 6.7.1"
    # Branche 6 maintenue : pas d'obsolescence.
    assert _par_identifiant(resultats, "cms_obsolete") is None


def test_cms_obsolete_wordpress_branche_non_maintenue(respx_mock):
    """Un WordPress 5.0 (branche 5 non maintenue) produit cms_obsolete ELEVEE."""
    _mocker_accueil(respx_mock, _generateur("WordPress 5.0"))

    resultats = _executer()

    obsolete = _par_identifiant(resultats, "cms_obsolete")
    assert obsolete is not None
    assert obsolete.reussi is False
    assert obsolete.gravite is Gravite.ELEVEE
    assert "5.0" in obsolete.preuve
    assert obsolete.details["branche"] == "5"


def test_drupal_detecte_via_x_generator(respx_mock):
    """L'en-tête X-Generator « Drupal 7 (…) » suffit à identifier Drupal (sans version)."""
    _mocker_accueil(
        respx_mock, "<html></html>", headers={"x-generator": "Drupal 7 (https://www.drupal.org)"}
    )

    resultats = _executer()

    detecte = _par_identifiant(resultats, "cms_detecte")
    assert detecte is not None
    assert detecte.details["cms"] == "Drupal"
    # « 7 » seul n'est pas un numéro de version complet : aucune version déduite.
    assert detecte.details["version"] is None
    assert _par_identifiant(resultats, "cms_obsolete") is None


def test_prestashop_detecte_via_cookie(respx_mock):
    """Un cookie de session « PrestaShop-<hash> » identifie PrestaShop."""
    _mocker_accueil(
        respx_mock,
        "<html><body>Boutique</body></html>",
        headers={"set-cookie": "PrestaShop-a1b2c3d4=xyz; path=/; HttpOnly"},
    )

    resultats = _executer()

    detecte = _par_identifiant(resultats, "cms_detecte")
    assert detecte is not None
    assert detecte.details["cms"] == "PrestaShop"


def test_mot_cle_nu_joomla_ne_declenche_pas_de_detection(respx_mock):
    """Non-régression : une page qui cite « Joomla » dans un texte n'est pas un site Joomla."""
    _mocker_accueil(
        respx_mock,
        "<html><body><p>Notre agence migre vos sites Joomla et PrestaShop.</p></body></html>",
    )

    resultats = _executer()

    assert _identifiants(resultats) == {"cms_non_detecte"}
    assert resultats[0].reussi is True


# --- Mode passif : page d'accueil uniquement ---------------------------------


def test_mode_passif_ne_lit_que_la_page_d_accueil(respx_mock):
    """Mode passif + WordPress : ni sonde de chemins, ni xmlrpc.php, ni /?author=1.

    Seule la page d'accueil est mockée : toute autre requête lèverait une erreur respx.
    """
    _mocker_accueil(respx_mock, _generateur("WordPress 5.0"))

    resultats = _executer(mode="passif")

    assert len(respx_mock.calls) == 1
    requete = respx_mock.calls.last.request
    assert str(requete.url) == f"{_BASE}/"
    assert "wp_xmlrpc_actif" not in _identifiants(resultats)
    assert "wp_enumeration_utilisateurs" not in _identifiants(resultats)


def test_mode_passif_sans_cms_ne_sonde_aucun_chemin(respx_mock):
    """Mode passif sans indice sur l'accueil : cms_non_detecte, aucune sonde de chemins."""
    _mocker_accueil(respx_mock, "<html><body>Bonjour</body></html>")

    resultats = _executer(mode="passif")

    assert len(respx_mock.calls) == 1
    assert _identifiants(resultats) == {"cms_non_detecte"}


# --- Mode actif : sonde de chemins -------------------------------------------


def test_cms_non_detecte_quand_aucun_indice(respx_mock):
    """Mode actif : accueil neutre, sonde soft 404 en 404, chemins absents -> cms_non_detecte."""
    _mocker_sonde_404(respx_mock)
    _mocker_chemins_absents(respx_mock)
    _mocker_accueil(respx_mock, "<html><body>Bonjour</body></html>")

    resultats = _executer(mode="actif")

    assert len(resultats) == 1
    assert resultats[0].identifiant == "cms_non_detecte"
    assert resultats[0].reussi is True
    assert resultats[0].gravite is Gravite.INFO
    # La sonde soft 404 a bien été envoyée sur un chemin aléatoire.
    urls = [str(appel.request.url) for appel in respx_mock.calls]
    assert any("/pmescan-" in url for url in urls)


def test_joomla_detecte_via_manifeste(respx_mock):
    """Mode actif : manifeste joomla.xml <extension> 4.4.9 -> Joomla détecté et obsolète."""
    _mocker_sonde_404(respx_mock)
    _mocker_chemins_absents(respx_mock, sauf=("/administrator/manifests/files/joomla.xml",))
    respx_mock.get(f"{_BASE}/administrator/manifests/files/joomla.xml").mock(
        return_value=httpx.Response(
            200,
            text=(
                '<?xml version="1.0" encoding="utf-8"?>\n'
                '<extension type="file" method="upgrade">\n'
                "  <name>files_joomla</name>\n"
                "  <version>4.4.9</version>\n"
                "</extension>\n"
            ),
        )
    )
    _mocker_accueil(respx_mock, "<html><body>Bonjour</body></html>")

    resultats = _executer(mode="actif")

    detecte = _par_identifiant(resultats, "cms_detecte")
    assert detecte is not None
    assert detecte.preuve == "Joomla 4.4.9"
    # Branche 4 < plus petite branche maintenue (5) : obsolète.
    assert _par_identifiant(resultats, "cms_obsolete") is not None


def test_soft_404_ne_produit_pas_de_faux_obsolete(respx_mock):
    """Non-régression soft 404 : le site renvoie 200 partout avec le même corps.

    Le corps contient « <title>WordPress</title> … Version 2.0 » : sans la sonde soft
    404, readme.html serait pris pour un WordPress 2.0 obsolète. Il ne doit rien en être.
    """
    corps = "<html><head><title>WordPress</title></head><body>Version 2.0</body></html>"
    respx_mock.get(url__regex=rf"{_BASE}/.*").mock(
        return_value=httpx.Response(200, text=corps)
    )

    resultats = _executer(mode="actif")

    assert _identifiants(resultats) == {"cms_non_detecte"}
    assert _par_identifiant(resultats, "cms_obsolete") is None


def test_soft_404_dynamique_ne_produit_pas_de_detection(respx_mock):
    """Non-régression soft 404 DYNAMIQUE : 200 partout, corps qui reprend le chemin demandé.

    Les corps diffèrent d'une URL à l'autre (le chemin y figure), donc une simple
    comparaison avec la page de la sonde ne suffirait pas. Le corps porte aussi toutes
    les signatures de readme.html (<title> WordPress, logo, lien wordpress.org,
    « <br />Version 2.0 ») : seule la sonde soft 404 peut empêcher un faux WordPress 2.0.
    """

    def _page_fourre_tout(request: httpx.Request) -> httpx.Response:
        corps = (
            "<html><head><title>Agence WordPress Dakar</title></head><body>"
            '<h1 id="logo">Agence</h1>'
            '<a href="https://wordpress.org/">Nos sites</a>'
            f"<p>Page demandée : {request.url.path}</p>"
            "<p>Découvrez la version 2.0 de notre offre.<br />Version 2.0 disponible.</p>"
            "</body></html>"
        )
        return httpx.Response(200, text=corps)

    respx_mock.get(url__regex=rf"{_BASE}/.*").mock(side_effect=_page_fourre_tout)

    resultats = _executer(mode="actif")

    assert _identifiants(resultats) == {"cms_non_detecte"}
    assert _par_identifiant(resultats, "cms_obsolete") is None
    # Sonde en 200 : on s'arrête là, aucun fichier de version n'est demandé ensuite.
    chemins = [appel.request.url.path for appel in respx_mock.calls]
    assert chemins[0] == "/"
    assert chemins[1].startswith("/pmescan-")
    assert len(chemins) == 2


# --- Signature stricte de readme.html (mode actif) ---------------------------


def _mocker_readme(routeur, corps: str) -> None:
    """Accueil neutre, sonde soft 404 en 404, readme.html = ``corps``, autres chemins 404.

    Les sondes WordPress (xmlrpc, /?author=1) sont enregistrées AVANT l'accueil.
    """
    _mocker_wordpress_sain(routeur)
    _mocker_sonde_404(routeur)
    _mocker_chemins_absents(routeur, sauf=("/readme.html",))
    routeur.get(f"{_BASE}/readme.html").mock(return_value=httpx.Response(200, text=corps))
    _mocker_accueil(routeur, "<html><body>Bonjour</body></html>")


def test_readme_sans_marqueur_n_est_pas_wordpress(respx_mock):
    """readme.html avec un <title> WordPress mais sans logo ni lien wordpress.org : rien."""
    _mocker_readme(
        respx_mock,
        "<html><head><title>WordPress &rsaquo; ReadMe</title></head>"
        "<body><br />Version 5.0</body></html>",
    )

    resultats = _executer(mode="actif")

    assert _identifiants(resultats) == {"cms_non_detecte"}


@pytest.mark.parametrize(
    "marqueur",
    ['<h1 id="logo">WordPress</h1>', '<a href="https://wordpress.org/">wordpress.org</a>'],
    ids=["logo", "lien_wordpress_org"],
)
def test_readme_avec_marqueur_sans_br_version_none(respx_mock, marqueur):
    """Marqueur présent mais « Version » sans <br> devant : WordPress sans version."""
    _mocker_readme(
        respx_mock,
        f"<html><head><title>WordPress &rsaquo; ReadMe</title></head><body>{marqueur}"
        "<p>Version 5.0</p></body></html>",
    )

    resultats = _executer(mode="actif")

    detecte = _par_identifiant(resultats, "cms_detecte")
    assert detecte is not None
    assert detecte.details == {"cms": "WordPress", "version": None}
    assert _par_identifiant(resultats, "cms_obsolete") is None


def test_readme_avec_marqueur_et_br_version_donne_obsolete(respx_mock):
    """Marqueur + « <br />Version 5.0 » : WordPress 5.0 détecté, donc cms_obsolete."""
    _mocker_readme(
        respx_mock,
        '<html><head><title>WordPress &rsaquo; ReadMe</title></head><body>'
        '<h1 id="logo"><a href="https://wordpress.org/">WordPress</a><br />Version 5.0</h1>'
        "</body></html>",
    )

    resultats = _executer(mode="actif")

    detecte = _par_identifiant(resultats, "cms_detecte")
    assert detecte is not None
    assert detecte.preuve == "WordPress 5.0"
    obsolete = _par_identifiant(resultats, "cms_obsolete")
    assert obsolete is not None
    assert obsolete.gravite is Gravite.ELEVEE


# --- Logique de branche maintenue --------------------------------------------


@pytest.mark.parametrize(
    ("version", "maintenues", "attendu"),
    [
        ("6.7.1", {"6", "7"}, None),  # branche maintenue
        ("8.0", {"6", "7"}, None),  # branche plus récente que la table : pas de faux positif
        ("5.9.3", {"6", "7"}, "5"),  # ancienne branche
        ("7.98", {"10", "11"}, "7"),  # comparaison numérique, pas lexicographique
        ("abc", {"6", "7"}, None),  # format invalide
        ("", {"6", "7"}, None),  # version vide
        ("5.0", set(), None),  # table vide : on ne conclut rien
    ],
    ids=["maintenue", "plus_recente", "ancienne", "numerique", "invalide", "vide", "table_vide"],
)
def test_branche_non_maintenue(version, maintenues, attendu):
    """_branche_non_maintenue ne signale que les branches strictement plus anciennes."""
    assert _branche_non_maintenue(version, maintenues) == attendu


def test_table_des_branches_couvre_les_cms_suivis():
    """Chaque CMS suivi a une table de branches maintenues non vide et numérique."""
    assert set(BRANCHES_MAINTENUES) == {"WordPress", "Joomla", "Drupal", "PrestaShop"}
    for branches in BRANCHES_MAINTENUES.values():
        assert branches
        assert all(branche.isdigit() for branche in branches)


# --- OSV : opt-in ------------------------------------------------------------


def test_osv_non_contacte_quand_verifier_cve_desactive(respx_mock):
    """verifier_cve=False : aucune requête vers api.osv.dev, pas de cms_vulnerable."""
    _mocker_accueil(respx_mock, _generateur("Drupal 7.98"))
    route_osv = respx_mock.post(_URL_OSV).mock(
        return_value=httpx.Response(200, json={"vulns": [{"id": "CVE-0000-0000"}]})
    )

    resultats = _executer(verifier_cve=False)

    # L'API tierce ne doit pas avoir été appelée.
    assert route_osv.called is False
    assert _par_identifiant(resultats, "cms_vulnerable") is None
    assert _par_identifiant(resultats, "cms_cve_indeterminee") is None
    # L'obsolescence reste évaluée localement.
    assert _par_identifiant(resultats, "cms_obsolete") is not None


def test_osv_vulnerable_quand_verifier_cve_actif(respx_mock):
    """verifier_cve=True + Drupal 10.1 + OSV renvoie des vulns : cms_vulnerable CRITIQUE."""
    _mocker_accueil(respx_mock, _generateur("Drupal 10.1"))
    route_osv = respx_mock.post(_URL_OSV).mock(
        return_value=httpx.Response(
            200, json={"vulns": [{"id": "CVE-2024-1111"}, {"id": "CVE-2024-2222"}]}
        )
    )

    resultats = _executer(verifier_cve=True)

    vulnerable = _par_identifiant(resultats, "cms_vulnerable")
    assert vulnerable is not None
    assert vulnerable.reussi is False
    assert vulnerable.gravite is Gravite.CRITIQUE
    assert "CVE-2024-1111" in vulnerable.preuve
    assert vulnerable.details["cve"] == ["CVE-2024-1111", "CVE-2024-2222"]
    # Confidentialité : seuls le paquet et la version partent vers OSV, jamais le domaine.
    contenu = route_osv.calls.last.request.content.decode("utf-8")
    assert json.loads(contenu) == {
        "version": "10.1",
        "package": {"name": "drupal/core", "ecosystem": "Packagist"},
    }
    assert DOMAINE not in contenu


def test_pas_de_cms_obsolete_quand_cms_vulnerable(respx_mock):
    """Drupal 7.98 (branche abandonnée) + failles OSV : cms_vulnerable seul, sans cms_obsolete."""
    _mocker_accueil(respx_mock, _generateur("Drupal 7.98"))
    respx_mock.post(_URL_OSV).mock(
        return_value=httpx.Response(200, json={"vulns": [{"id": "CVE-2025-0001"}]})
    )

    resultats = _executer(verifier_cve=True)

    assert _par_identifiant(resultats, "cms_vulnerable") is not None
    assert _par_identifiant(resultats, "cms_obsolete") is None


def test_osv_indetermine_quand_injoignable(respx_mock):
    """verifier_cve=True + Drupal + OSV injoignable : cms_cve_indeterminee INFO, sans exception."""
    _mocker_accueil(respx_mock, _generateur("Drupal 10.1"))
    route_osv = respx_mock.post(_URL_OSV).mock(
        side_effect=httpx.ConnectError("osv injoignable")
    )

    resultats = _executer(verifier_cve=True)

    assert route_osv.called is True
    indetermine = _par_identifiant(resultats, "cms_cve_indeterminee")
    assert indetermine is not None
    assert indetermine.reussi is False
    assert indetermine.gravite is Gravite.INFO
    assert indetermine.details["motif"] == "OSV injoignable"
    # Pas de faux positif de vulnérabilité en cas d'indisponibilité.
    assert _par_identifiant(resultats, "cms_vulnerable") is None


def test_wordpress_non_couvert_par_osv(respx_mock):
    """verifier_cve=True + WordPress : cms_cve_indeterminee sans aucun appel à OSV."""
    _mocker_accueil(respx_mock, _generateur("WordPress 6.7.1"))
    route_osv = respx_mock.post(_URL_OSV).mock(return_value=httpx.Response(200, json={}))

    resultats = _executer(verifier_cve=True)

    assert route_osv.called is False
    indetermine = _par_identifiant(resultats, "cms_cve_indeterminee")
    assert indetermine is not None
    assert indetermine.details["motif"] == "CMS non couvert par OSV"


@pytest.mark.parametrize(
    ("reponse", "motif"),
    [
        (httpx.Response(503, text="indisponible"), "OSV a répondu 503"),
        (httpx.Response(200, content=b"<html>pas du json</html>"), "réponse OSV illisible"),
        (httpx.Response(200, json={"vulns": [{"summary": "sans id"}, {"id": ""}]}),
         "réponse OSV sans identifiant"),
        (httpx.Response(200, json={"vulns": "pas une liste"}), "réponse OSV illisible"),
    ],
    ids=["non_200", "json_illisible", "vulns_sans_id", "vulns_pas_liste"],
)
def test_osv_reponse_inexploitable_donne_indeterminee(respx_mock, reponse, motif):
    """Réponse OSV inexploitable : cms_cve_indeterminee avec le motif adéquat, sans exception."""
    _mocker_accueil(respx_mock, _generateur("Drupal 10.1"))
    respx_mock.post(_URL_OSV).mock(return_value=reponse)

    resultats = _executer(verifier_cve=True)

    indetermine = _par_identifiant(resultats, "cms_cve_indeterminee")
    assert indetermine is not None
    assert indetermine.details["motif"] == motif
    assert _par_identifiant(resultats, "cms_vulnerable") is None


@pytest.mark.parametrize("charge", [{"vulns": []}, {}], ids=["vulns_vide", "sans_cle_vulns"])
def test_osv_sans_faille_n_emet_rien(respx_mock, charge):
    """OSV ne connaît aucune faille : ni cms_vulnerable ni cms_cve_indeterminee."""
    _mocker_accueil(respx_mock, _generateur("Drupal 10.1"))
    respx_mock.post(_URL_OSV).mock(return_value=httpx.Response(200, json=charge))

    resultats = _executer(verifier_cve=True)

    assert _identifiants(resultats) == {"cms_detecte"}


def test_osv_redirection_non_suivie(respx_mock):
    """OSV répond 301 : cms_cve_indeterminee (motif « 301 »), la redirection n'est pas suivie."""
    _mocker_accueil(respx_mock, _generateur("Drupal 10.1"))
    cible_redirection = "https://redirige.exemple.net/v1/query"
    respx_mock.post(_URL_OSV).mock(
        return_value=httpx.Response(301, headers={"location": cible_redirection})
    )
    route_redirection = respx_mock.route(url=cible_redirection).mock(
        return_value=httpx.Response(200, json={"vulns": [{"id": "CVE-PIEGE"}]})
    )

    resultats = _executer(verifier_cve=True)

    assert route_redirection.called is False
    indetermine = _par_identifiant(resultats, "cms_cve_indeterminee")
    assert indetermine is not None
    assert "301" in indetermine.details["motif"]
    assert _par_identifiant(resultats, "cms_vulnerable") is None


def test_client_osv_verifie_le_certificat_et_ne_suit_pas_les_redirections(
    respx_mock, monkeypatch
):
    """Le client OSV est créé avec verify=True et follow_redirects=False.

    On espionne httpx.AsyncClient (sous-classe qui enregistre ses arguments) : le client
    de la cible garde verify=False, celui d'OSV est distinct et vérifié.
    """
    arguments: list[dict] = []
    vrai_client = httpx.AsyncClient

    class _ClientEspion(vrai_client):
        def __init__(self, *args, **kwargs):
            arguments.append(kwargs)
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(cms_module.httpx, "AsyncClient", _ClientEspion)
    _mocker_accueil(respx_mock, _generateur("Drupal 10.1"))
    respx_mock.post(_URL_OSV).mock(return_value=httpx.Response(200, json={"vulns": []}))

    _executer(verifier_cve=True)

    assert len(arguments) == 2
    client_cible, client_osv = arguments
    assert client_cible["verify"] is False
    assert client_osv["verify"] is True
    assert client_osv["follow_redirects"] is False


# --- Vérifications propres à WordPress (mode actif) --------------------------


def test_wp_xmlrpc_actif_detecte(respx_mock):
    """Mode actif : xmlrpc.php répondant « XML-RPC » produit wp_xmlrpc_actif FAIBLE."""
    respx_mock.get(f"{_BASE}/xmlrpc.php").mock(
        return_value=httpx.Response(405, text="XML-RPC server accepts POST requests only.")
    )
    respx_mock.get(url=f"{_BASE}/", params={"author": "1"}).mock(
        return_value=httpx.Response(200, text="page auteur")
    )
    _mocker_accueil(respx_mock, _generateur("WordPress 6.7.1"))

    resultats = _executer(mode="actif")

    xmlrpc = _par_identifiant(resultats, "wp_xmlrpc_actif")
    assert xmlrpc is not None
    assert xmlrpc.reussi is False
    assert xmlrpc.gravite is Gravite.FAIBLE


def test_wp_enumeration_utilisateurs_detecte(respx_mock):
    """/?author=1 redirigeant vers /author/<nom>/ (200) produit wp_enumeration_utilisateurs."""
    respx_mock.get(f"{_BASE}/xmlrpc.php").mock(return_value=httpx.Response(404))
    # Route « /?author=1 » AVANT la page d'accueil (la première route qui correspond gagne).
    respx_mock.get(url=f"{_BASE}/", params={"author": "1"}).mock(
        return_value=httpx.Response(301, headers={"location": f"{_BASE}/author/admin/"})
    )
    respx_mock.get(f"{_BASE}/author/admin/").mock(
        return_value=httpx.Response(200, text="profil admin")
    )
    _mocker_accueil(respx_mock, _generateur("WordPress 6.7.1"))

    resultats = _executer(mode="actif")

    enumeration = _par_identifiant(resultats, "wp_enumeration_utilisateurs")
    assert enumeration is not None
    assert enumeration.reussi is False
    assert enumeration.gravite is Gravite.MOYENNE
    assert enumeration.preuve == f"{_BASE}/author/admin/"


def test_wp_enumeration_sans_redirection_n_emet_rien(respx_mock):
    """/?author=1 qui ne redirige pas vers /author/ : pas d'énumération signalée."""
    _mocker_wordpress_sain(respx_mock)
    _mocker_accueil(respx_mock, _generateur("WordPress 6.7.1"))

    resultats = _executer(mode="actif")

    assert _par_identifiant(resultats, "wp_enumeration_utilisateurs") is None
    assert _par_identifiant(resultats, "wp_xmlrpc_actif") is None


def test_wp_enumeration_page_finale_non_200_n_emet_rien(respx_mock):
    """Redirection vers /author/admin/ qui répond 404 : la redirection ne prouve rien."""
    respx_mock.get(f"{_BASE}/xmlrpc.php").mock(return_value=httpx.Response(404))
    respx_mock.get(url=f"{_BASE}/", params={"author": "1"}).mock(
        return_value=httpx.Response(301, headers={"location": f"{_BASE}/author/admin/"})
    )
    respx_mock.get(f"{_BASE}/author/admin/").mock(return_value=httpx.Response(404))
    _mocker_accueil(respx_mock, _generateur("WordPress 6.7.1"))

    resultats = _executer(mode="actif")

    assert _par_identifiant(resultats, "wp_enumeration_utilisateurs") is None


# --- Robustesse réseau -------------------------------------------------------


@pytest.mark.parametrize("mode", ["passif", "actif"])
def test_erreur_reseau_generale_ne_leve_pas(respx_mock, mode):
    """Toute requête en erreur réseau : pas d'exception, CMS non détecté (réussi)."""
    respx_mock.get(url__regex=rf"{_BASE}.*").mock(
        side_effect=httpx.ConnectError("connexion refusée")
    )

    resultats = _executer(mode=mode)

    assert len(resultats) == 1
    assert resultats[0].identifiant == "cms_non_detecte"
    assert resultats[0].reussi is True


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
