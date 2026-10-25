"""Tests hors-ligne de la vérification des en-têtes HTTP de sécurité et des cookies."""

import asyncio

import httpx
import pytest
import respx

from pmescan.checks.entetes import VerificationEntetes
from pmescan.modele import Gravite
from tests.conftest import charger_fixture


def _reponse_depuis_fixture(nom: str) -> httpx.Response:
    """Fabrique une réponse httpx à partir d'une fixture enregistrée."""
    donnees = charger_fixture(nom)
    entetes = list(donnees["entetes"].items())
    for cookie in donnees.get("cookies", []):
        entetes.append(("set-cookie", cookie))
    return httpx.Response(donnees["statut"], headers=entetes)


def _par_identifiant(resultats, identifiant):
    return next((r for r in resultats if r.identifiant == identifiant), None)


@respx.mock
def test_entetes_hsts_absent_renvoie_probleme(cible_exemple):
    """Une réponse sans HSTS produit entete_hsts_absent en gravité moyenne, non réussi."""
    respx.get("https://exemple.com/").mock(
        return_value=_reponse_depuis_fixture("entetes_non_securises.json")
    )

    resultats = asyncio.run(VerificationEntetes().executer(cible_exemple))

    resultat = _par_identifiant(resultats, "entete_hsts_absent")
    assert resultat is not None
    assert resultat.reussi is False
    assert resultat.gravite is Gravite.MOYENNE


@respx.mock
def test_entetes_tous_presents_renvoient_reussi(cible_exemple):
    """Quand tous les en-têtes de sécurité sont là, chaque résultat est réussi."""
    respx.get("https://exemple.com/").mock(
        return_value=_reponse_depuis_fixture("entetes_securises.json")
    )

    resultats = asyncio.run(VerificationEntetes().executer(cible_exemple))

    resultat = _par_identifiant(resultats, "entete_hsts_present")
    assert resultat is not None
    assert resultat.reussi is True
    # Aucun en-tête de sécurité ne doit être signalé absent.
    assert not any(r.identifiant.endswith("_absent") for r in resultats)


@respx.mock
def test_cookie_non_securise_detecte(cible_exemple):
    """Un cookie sans Secure/HttpOnly/SameSite produit cookie_non_securise en gravité élevée."""
    respx.get("https://exemple.com/").mock(
        return_value=_reponse_depuis_fixture("entetes_non_securises.json")
    )

    resultats = asyncio.run(VerificationEntetes().executer(cible_exemple))

    resultat = _par_identifiant(resultats, "cookie_non_securise")
    assert resultat is not None
    assert resultat.reussi is False
    assert resultat.gravite is Gravite.ELEVEE
    assert set(resultat.details["attributs_manquants"]) == {"Secure", "HttpOnly", "SameSite"}


@respx.mock
def test_cookies_securises_renvoie_reussi(cible_exemple):
    """Un cookie portant Secure, HttpOnly et SameSite produit cookies_securises réussi."""
    respx.get("https://exemple.com/").mock(
        return_value=_reponse_depuis_fixture("entetes_securises.json")
    )

    resultats = asyncio.run(VerificationEntetes().executer(cible_exemple))

    resultat = _par_identifiant(resultats, "cookies_securises")
    assert resultat is not None
    assert resultat.reussi is True


@respx.mock
def test_entete_fuite_version_detecte(cible_exemple):
    """Un en-tête Server révélant une version produit entete_fuite_version en gravité faible."""
    respx.get("https://exemple.com/").mock(
        return_value=_reponse_depuis_fixture("entetes_non_securises.json")
    )

    resultats = asyncio.run(VerificationEntetes().executer(cible_exemple))

    resultat = _par_identifiant(resultats, "entete_fuite_version")
    assert resultat is not None
    assert resultat.reussi is False
    assert resultat.gravite is Gravite.FAIBLE
    assert "Apache/2.4.41" in resultat.preuve


@respx.mock
def test_entetes_injoignable_ne_leve_pas(cible_exemple):
    """Un hôte injoignable renvoie entetes_injoignable sans lever d'exception."""
    respx.get("https://exemple.com/").mock(
        side_effect=httpx.ConnectError("connexion refusée")
    )

    resultats = asyncio.run(VerificationEntetes().executer(cible_exemple))

    assert len(resultats) == 1
    assert resultats[0].identifiant == "entetes_injoignable"
    assert resultats[0].reussi is False


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
