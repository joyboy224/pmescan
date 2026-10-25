"""Tests de l'orchestrateur : sélection des vérifications selon le mode de la cible."""

import asyncio

import httpx
import pytest

import pmescan.scanner as scanner_module
from pmescan.checks.base import Verification
from pmescan.modele import Cible, Gravite, Resultat
from pmescan.scanner import scanner, selectionner_verifications


class VerificationPassive(Verification):
    """Faux check passif qui marque son exécution."""

    nom = "faux_passif"
    niveau_minimum = "passif"

    async def executer(self, cible: Cible) -> list[Resultat]:
        return [Resultat(identifiant="passif_ok", gravite=Gravite.INFO, reussi=True)]


class VerificationActive(Verification):
    """Faux check actif qui ne doit pas s'exécuter en mode passif."""

    nom = "faux_actif"
    niveau_minimum = "actif"

    async def executer(self, cible: Cible) -> list[Resultat]:
        return [Resultat(identifiant="actif_ok", gravite=Gravite.INFO, reussi=True)]


class VerificationQuiLeve(Verification):
    """Faux check passif qui lève toujours une exception."""

    nom = "faux_casse"
    niveau_minimum = "passif"

    async def executer(self, cible: Cible) -> list[Resultat]:
        raise RuntimeError("boom interne")


def test_selection_mode_passif_retient_les_checks_passifs():
    """En mode passif, seuls les checks passifs (TLS, en-têtes, DNS/mail, CMS) sont retenus.

    Les checks intrusifs « exposes » et « ports » (niveau actif) en sont exclus.
    """
    verifications = selectionner_verifications("passif")
    noms = {v.nom for v in verifications}
    assert noms == {"tls", "entetes", "dns_mail", "cms"}


# --- Défense en profondeur : autorisation explicite ---------------------------

_NOMS_PASSIFS = {"tls", "entetes", "dns_mail", "cms"}
_NOMS_TOUS = _NOMS_PASSIFS | {"exposes", "ports"}


@pytest.mark.parametrize(
    ("mode", "autorisation", "attendus"),
    [
        ("passif", False, _NOMS_PASSIFS),
        ("passif", True, _NOMS_PASSIFS),  # l'autorisation n'ajoute rien en passif
        ("actif", False, _NOMS_PASSIFS),  # mode intrusif SANS autorisation : exclus
        ("agressif", False, _NOMS_PASSIFS),
        ("actif", True, _NOMS_TOUS),
        ("agressif", True, _NOMS_TOUS),
    ],
    ids=[
        "passif_sans",
        "passif_avec",
        "actif_sans",
        "agressif_sans",
        "actif_avec",
        "agressif_avec",
    ],
)
def test_selection_exige_l_autorisation_pour_les_checks_intrusifs(mode, autorisation, attendus):
    """selectionner_verifications n'inclut exposes/ports qu'en mode intrusif AUTORISÉ."""
    noms = {v.nom for v in selectionner_verifications(mode, autorisation)}
    assert noms == attendus


def test_selection_autorisation_false_par_defaut():
    """Sans argument, l'autorisation vaut False : aucun check intrusif en mode actif."""
    noms = {v.nom for v in selectionner_verifications("actif")}
    assert noms == _NOMS_PASSIFS


def _brancher_checks_reseau(monkeypatch) -> dict:
    """Restreint VERIFICATIONS à cms + exposes + ports et instrumente le réseau TCP/DNS.

    Renvoie un compteur des résolutions et connexions TCP tentées par le check ports.
    """
    from pmescan.checks.cms import VerificationCms
    from pmescan.checks.exposes import VerificationFichiersExposes
    from pmescan.checks.ports import VerificationPorts

    monkeypatch.setattr(
        scanner_module,
        "VERIFICATIONS",
        [VerificationCms(), VerificationFichiersExposes(), VerificationPorts()],
    )
    compteur = {"resolutions": 0, "connexions": 0}

    async def _faux_resoudre(self, hote):
        compteur["resolutions"] += 1
        return "192.0.2.10"

    async def _fausse_connexion(hote, port):
        compteur["connexions"] += 1
        raise OSError("connexion refusée")

    monkeypatch.setattr(VerificationPorts, "_resoudre", _faux_resoudre)
    monkeypatch.setattr(asyncio, "open_connection", _fausse_connexion)
    return compteur


@pytest.mark.respx(assert_all_called=False)
@pytest.mark.parametrize("mode", ["actif", "agressif"])
def test_scanner_mode_intrusif_sans_autorisation_n_execute_aucun_check_intrusif(
    monkeypatch, respx_mock, mode
):
    """Cible en mode intrusif SANS autorisation (API Python) : rien d'intrusif ne part.

    Seule la page d'accueil est mockée : toute requête vers un chemin sensible
    (/.env, /.git/HEAD, readme.html…) lèverait une erreur respx, que scanner()
    convertirait en « *_erreur_interne ».
    """
    compteur = _brancher_checks_reseau(monkeypatch)
    respx_mock.get("https://exemple.com/").mock(
        return_value=httpx.Response(200, text="<html><body>Bonjour</body></html>")
    )

    resultats = asyncio.run(scanner(Cible(domaine="exemple.com", mode=mode)))

    identifiants = {r.identifiant for r in resultats}
    assert identifiants == {"cms_non_detecte"}
    # Une seule requête HTTP, vers la page d'accueil (cms passif).
    assert [str(appel.request.url) for appel in respx_mock.calls] == ["https://exemple.com/"]
    # Le check ports n'a ni résolu l'hôte ni tenté la moindre connexion.
    assert compteur == {"resolutions": 0, "connexions": 0}


@pytest.mark.respx(assert_all_called=False)
def test_scanner_mode_actif_avec_autorisation_execute_les_checks_intrusifs(
    monkeypatch, respx_mock
):
    """Avec autorisation=True, exposes, ports et la sonde de chemins cms s'exécutent."""
    compteur = _brancher_checks_reseau(monkeypatch)
    respx_mock.get("https://exemple.com/").mock(
        return_value=httpx.Response(200, text="<html><body>Bonjour</body></html>")
    )
    respx_mock.get(url__regex=r"https://exemple\.com/.+").mock(
        return_value=httpx.Response(404)
    )

    cible = Cible(domaine="exemple.com", mode="actif", autorisation=True)
    resultats = asyncio.run(scanner(cible))

    identifiants = {r.identifiant for r in resultats}
    assert {"cms_non_detecte", "aucun_fichier_expose", "aucun_port_sensible"} <= identifiants
    chemins = {appel.request.url.path for appel in respx_mock.calls}
    assert {"/.env", "/.git/HEAD", "/readme.html"} <= chemins
    assert compteur["resolutions"] == 1
    assert compteur["connexions"] > 0


def test_scanner_mode_passif_ignore_les_checks_actifs(monkeypatch):
    """scanner() en mode passif exécute le check passif et ignore le check actif."""
    monkeypatch.setattr(
        scanner_module, "VERIFICATIONS", [VerificationPassive(), VerificationActive()]
    )
    cible = Cible(domaine="exemple.com", mode="passif")

    resultats = asyncio.run(scanner(cible))

    identifiants = {r.identifiant for r in resultats}
    assert identifiants == {"passif_ok"}


def test_scanner_mode_actif_execute_tous_les_checks(monkeypatch):
    """scanner() en mode actif AUTORISÉ exécute aussi bien les checks passifs qu'actifs."""
    monkeypatch.setattr(
        scanner_module, "VERIFICATIONS", [VerificationPassive(), VerificationActive()]
    )
    cible = Cible(domaine="exemple.com", mode="actif", autorisation=True)

    resultats = asyncio.run(scanner(cible))

    identifiants = {r.identifiant for r in resultats}
    assert identifiants == {"passif_ok", "actif_ok"}


def test_scanner_convertit_exception_en_resultat(monkeypatch):
    """Une vérification qui lève ne plante pas scanner() : elle devient un Resultat d'erreur."""
    monkeypatch.setattr(scanner_module, "VERIFICATIONS", [VerificationQuiLeve()])
    cible = Cible(domaine="exemple.com", mode="passif")

    # scanner() ne doit PAS propager l'exception.
    resultats = asyncio.run(scanner(cible))

    assert len(resultats) == 1
    resultat = resultats[0]
    assert resultat.identifiant == "faux_casse_erreur_interne"
    assert resultat.reussi is False
    assert resultat.gravite == Gravite.INFO
    # Le message de l'exception est conservé dans la preuve.
    assert resultat.preuve == "boom interne"


def test_scanner_isole_la_panne_d_un_check(monkeypatch):
    """La panne d'un check ne supprime pas les résultats des autres vérifications."""
    monkeypatch.setattr(
        scanner_module, "VERIFICATIONS", [VerificationQuiLeve(), VerificationPassive()]
    )
    cible = Cible(domaine="exemple.com", mode="passif")

    resultats = asyncio.run(scanner(cible))

    identifiants = {r.identifiant for r in resultats}
    # Le résultat d'erreur de l'une ET le résultat normal de l'autre sont présents.
    assert identifiants == {"faux_casse_erreur_interne", "passif_ok"}


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
