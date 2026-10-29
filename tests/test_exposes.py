"""Tests hors-ligne de la vérification des fichiers exposés (mode actif).

On rejoue les réponses HTTP avec respx. On vérifie aussi, via scanner(), que ce
check intrusif ne s'exécute qu'à partir du mode actif.
"""

import asyncio

import httpx
import pytest
import respx

import pmescan.checks.exposes as exposes_module
import pmescan.scanner as scanner_module
from pmescan.checks.exposes import VerificationFichiersExposes
from pmescan.modele import Cible, Gravite
from pmescan.scanner import scanner

DOMAINE = "exemple.com"

# Les cinq chemins sensibles testés par le check.
_CHEMINS = ("/.git/HEAD", "/.env", "/backup.zip", "/phpinfo.php", "/")


def _par_identifiant(resultats, identifiant):
    return next((r for r in resultats if r.identifiant == identifiant), None)


def _mocker_tout_en_404() -> None:
    """Fait répondre 404 à tous les chemins sensibles et au chemin témoin aléatoire."""
    for chemin in _CHEMINS:
        respx.get(f"https://{DOMAINE}{chemin}").mock(return_value=httpx.Response(404))
    _mocker_temoin(httpx.Response(404))


def _mocker_temoin(reponse: httpx.Response) -> respx.Route:
    """Fait répondre ``reponse`` au chemin témoin (adresse inexistante, suffixe aléatoire)."""
    return respx.get(url__regex=rf"^https://{DOMAINE}/pmescan-inexistant-[0-9a-f]+$").mock(
        return_value=reponse
    )


def _executer():
    """Exécute la vérification des fichiers exposés sur exemple.com."""
    cible = Cible(domaine=DOMAINE, mode="actif", autorisation=True)
    return asyncio.run(VerificationFichiersExposes().executer(cible))


# --- Détection d'un fichier exposé -------------------------------------------


@respx.mock
def test_fichier_env_expose_detecte():
    """Un /.env renvoyant 200 avec des variables produit fichier_expose_env CRITIQUE."""
    _mocker_tout_en_404()
    respx.get(f"https://{DOMAINE}/.env").mock(
        return_value=httpx.Response(
            200, text="SECRET_KEY=abcdef123\nDB_PASSWORD=motdepasse\n"
        )
    )

    resultats = _executer()

    resultat = _par_identifiant(resultats, "fichier_expose_env")
    assert resultat is not None
    assert resultat.reussi is False
    assert resultat.gravite is Gravite.CRITIQUE
    assert resultat.preuve == f"https://{DOMAINE}/.env"
    # Rien d'autre n'est exposé : aucun_fichier_expose ne doit pas apparaître.
    assert _par_identifiant(resultats, "aucun_fichier_expose") is None


@respx.mock
def test_depot_git_expose_detecte():
    """Un /.git/HEAD renvoyant « ref: ... » produit fichier_expose_git CRITIQUE."""
    _mocker_tout_en_404()
    respx.get(f"https://{DOMAINE}/.git/HEAD").mock(
        return_value=httpx.Response(200, text="ref: refs/heads/main\n")
    )

    resultats = _executer()

    resultat = _par_identifiant(resultats, "fichier_expose_git")
    assert resultat is not None
    assert resultat.reussi is False
    assert resultat.gravite is Gravite.CRITIQUE


# --- Aucun fichier exposé -----------------------------------------------------


@respx.mock
def test_aucun_fichier_expose_quand_tout_en_404():
    """Si tous les chemins répondent 404, le check renvoie aucun_fichier_expose réussi."""
    _mocker_tout_en_404()

    resultats = _executer()

    assert len(resultats) == 1
    resultat = resultats[0]
    assert resultat.identifiant == "aucun_fichier_expose"
    assert resultat.reussi is True
    assert resultat.gravite is Gravite.INFO


# --- Erreur réseau sur un chemin ---------------------------------------------


@respx.mock
def test_erreur_reseau_sur_un_chemin_ne_leve_pas():
    """Une erreur réseau sur /.env n'interrompt pas le check (chemin ignoré)."""
    _mocker_tout_en_404()
    respx.get(f"https://{DOMAINE}/.env").mock(
        side_effect=httpx.ConnectError("connexion refusée")
    )

    # Aucune exception ne doit sortir ; comme rien n'est exposé, on obtient réussi.
    resultats = _executer()

    assert len(resultats) == 1
    assert resultats[0].identifiant == "aucun_fichier_expose"
    assert resultats[0].reussi is True


# --- Faux positifs : une réponse 200 ne suffit pas ----------------------------


@respx.mock
def test_site_qui_repond_200_partout_n_est_pas_signale():
    """Le serveur répond 200 et le même texte « CLE=valeur » à toute adresse : rien signalé."""
    page_unique = httpx.Response(
        200, text="APP=vitrine\n", headers={"content-type": "text/plain"}
    )
    for chemin in _CHEMINS:
        respx.get(f"https://{DOMAINE}{chemin}").mock(return_value=page_unique)
    _mocker_temoin(page_unique)

    resultats = _executer()

    assert [r.identifiant for r in resultats] == ["aucun_fichier_expose"]


@respx.mock
def test_env_en_html_n_est_pas_signale():
    """/.env renvoie une page HTML contenant « CLE=… » (page d'erreur, article) : ignoré."""
    _mocker_tout_en_404()
    respx.get(f"https://{DOMAINE}/.env").mock(
        return_value=httpx.Response(
            200,
            text="<!doctype html><html><body><pre>\nAPP_KEY=exemple\n</pre></body></html>",
            headers={"content-type": "text/html"},
        )
    )

    assert _par_identifiant(_executer(), "fichier_expose_env") is None


@respx.mock
def test_redirection_vers_l_accueil_n_est_pas_signalee():
    """/.env redirige vers l'accueil : la réponse finale ne vient pas de /.env, ignorée."""
    _mocker_tout_en_404()
    respx.get(f"https://{DOMAINE}/.env").mock(
        return_value=httpx.Response(302, headers={"location": f"https://{DOMAINE}/accueil"})
    )
    respx.get(f"https://{DOMAINE}/accueil").mock(
        return_value=httpx.Response(200, text="BIENVENUE=1\n")
    )

    assert _par_identifiant(_executer(), "fichier_expose_env") is None


@respx.mock
def test_git_head_doit_avoir_le_format_exact():
    """Une page qui contient « ref: » au milieu d'un texte n'est pas un .git/HEAD."""
    _mocker_tout_en_404()
    respx.get(f"https://{DOMAINE}/.git/HEAD").mock(
        return_value=httpx.Response(200, text="ref: voir la documentation en ligne")
    )

    assert _par_identifiant(_executer(), "fichier_expose_git") is None


@respx.mock
@pytest.mark.parametrize(
    ("contenu", "type_contenu", "expose"),
    [
        (b"PK\x03\x04" + b"\x00" * 26, "application/octet-stream", True),
        (b"<html>Page introuvable</html>", "application/zip", False),
    ],
    ids=["vraie_archive", "html_annonce_zip"],
)
def test_backup_zip_juge_sur_la_signature(contenu, type_contenu, expose):
    """backup.zip : seule la signature ZIP compte, pas le Content-Type annoncé."""
    _mocker_tout_en_404()
    respx.get(f"https://{DOMAINE}/backup.zip").mock(
        return_value=httpx.Response(200, content=contenu, headers={"content-type": type_contenu})
    )

    assert (_par_identifiant(_executer(), "fichier_expose_backup") is not None) is expose


@respx.mock
@pytest.mark.parametrize(
    ("page", "expose"),
    [
        ("<html><head><title>PHP 8.2.1 - phpinfo()</title></head></html>", True),
        ("<html><body>Notre site tourne sous PHP Version 8.</body></html>", False),
    ],
    ids=["vraie_page_phpinfo", "simple_mention"],
)
def test_phpinfo_juge_sur_le_titre(page, expose):
    """phpinfo.php : exige le titre « phpinfo() », pas une simple mention de PHP."""
    _mocker_tout_en_404()
    respx.get(f"https://{DOMAINE}/phpinfo.php").mock(return_value=httpx.Response(200, text=page))

    assert (_par_identifiant(_executer(), "fichier_expose_phpinfo") is not None) is expose


@respx.mock
@pytest.mark.parametrize(
    ("page", "expose"),
    [
        ("<html><head><title>Index of /</title></head></html>", True),
        ("<html><p>Comment désactiver la page Index of / sur Apache ?</p></html>", False),
    ],
    ids=["vrai_listing", "article"],
)
def test_listing_juge_sur_le_titre(page, expose):
    """Listing : exige « Index of / » en titre ou en-tête, pas dans un paragraphe."""
    _mocker_tout_en_404()
    respx.get(f"https://{DOMAINE}/").mock(return_value=httpx.Response(200, text=page))

    assert (_par_identifiant(_executer(), "fichier_expose_listing") is not None) is expose


@respx.mock
def test_lecture_bornee_a_la_taille_maximale():
    """Un très gros fichier n'est pas téléchargé en entier : lecture limitée à _TAILLE_MAX."""
    respx.get(f"https://{DOMAINE}/backup.zip").mock(
        return_value=httpx.Response(200, content=b"PK\x03\x04" + b"x" * 1_000_000)
    )

    async def _executer_lecture():
        async with httpx.AsyncClient() as client:
            return await exposes_module._lire(client, f"https://{DOMAINE}/backup.zip")

    page = asyncio.run(_executer_lecture())

    assert page is not None
    assert len(page.corps) == exposes_module._TAILLE_MAX


# --- Défense en profondeur : appel direct sans autorisation ------------------


@pytest.mark.parametrize("mode", ["actif", "agressif"])
def test_appel_direct_sans_autorisation_n_envoie_aucune_requete(respx_mock, mode):
    """executer() appelé DIRECTEMENT sans autorisation : [] et aucune requête HTTP.

    Le routeur respx n'a AUCUNE route : la moindre requête lèverait une erreur respx.
    """
    cible = Cible(domaine=DOMAINE, mode=mode)

    resultats = asyncio.run(VerificationFichiersExposes().executer(cible))

    assert resultats == []
    assert len(respx_mock.calls) == 0


# --- Activation par mode via scanner() ---------------------------------------


def test_scanner_passif_n_execute_pas_les_exposes(monkeypatch):
    """En mode passif, le check « exposes » (niveau actif) n'est pas exécuté."""
    monkeypatch.setattr(scanner_module, "VERIFICATIONS", [VerificationFichiersExposes()])
    cible = Cible(domaine=DOMAINE, mode="passif")

    # Aucun appel réseau ne doit avoir lieu : le check est filtré avant exécution.
    resultats = asyncio.run(scanner(cible))

    assert resultats == []


@respx.mock
def test_scanner_actif_execute_les_exposes(monkeypatch):
    """En mode actif, le check « exposes » s'exécute et produit un résultat."""
    monkeypatch.setattr(scanner_module, "VERIFICATIONS", [VerificationFichiersExposes()])
    _mocker_tout_en_404()
    cible = Cible(domaine=DOMAINE, mode="actif", autorisation=True)

    resultats = asyncio.run(scanner(cible))

    identifiants = {r.identifiant for r in resultats}
    assert identifiants == {"aucun_fichier_expose"}


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
