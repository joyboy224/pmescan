"""Tests hors-ligne de la vérification des fichiers exposés (mode actif).

On rejoue les réponses HTTP avec respx. On vérifie aussi, via scanner(), que ce
check intrusif ne s'exécute qu'à partir du mode actif.
"""

import asyncio

import httpx
import pytest
import respx

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
    """Fait répondre 404 à tous les chemins sensibles (rien n'est exposé)."""
    for chemin in _CHEMINS:
        respx.get(f"https://{DOMAINE}{chemin}").mock(return_value=httpx.Response(404))


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
