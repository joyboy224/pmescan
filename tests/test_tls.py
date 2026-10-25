"""Tests hors-ligne de la vérification TLS (certificat, protocoles, chiffrements, redirection)."""

import asyncio

import httpx
import pytest
import respx

import pmescan.checks.tls as tls_module
from pmescan.checks.tls import VerificationTls
from pmescan.modele import Gravite
from tests.conftest import (
    FauxChiffrement,
    FauxChiffrementAccepte,
    FauxResultatChiffrements,
    construire_rapport,
    construire_scan_result,
    tentative_chiffrements,
)


def _identifiants(resultats):
    """Raccourci : ensemble des identifiants présents dans une liste de résultats."""
    return {r.identifiant for r in resultats}


def _par_identifiant(resultats, identifiant):
    """Renvoie le premier résultat portant cet identifiant, ou None."""
    return next((r for r in resultats if r.identifiant == identifiant), None)


# --- Certificat --------------------------------------------------------------


def test_tls_certificat_expire_renvoie_resultat_critique():
    """Un certificat déjà expiré produit tls_expire en gravité critique, non réussi."""
    rapport = construire_rapport(construire_scan_result(jours_avant_expiration=-5))
    resultats = VerificationTls()._analyser_certificat(rapport)

    resultat = _par_identifiant(resultats, "tls_expire")
    assert resultat is not None
    assert resultat.reussi is False
    assert resultat.gravite is Gravite.CRITIQUE
    assert resultat.details["jours_restants"] < 0


def test_tls_expiration_proche_renvoie_resultat_moyen():
    """Un certificat qui expire dans moins de 30 jours produit tls_expiration_proche."""
    rapport = construire_rapport(construire_scan_result(jours_avant_expiration=10))
    resultats = VerificationTls()._analyser_certificat(rapport)

    resultat = _par_identifiant(resultats, "tls_expiration_proche")
    assert resultat is not None
    assert resultat.reussi is False
    assert resultat.gravite is Gravite.MOYENNE


def test_tls_certificat_valide_renvoie_reussi():
    """Un certificat valable longtemps produit tls_certificat_valide réussi."""
    rapport = construire_rapport(construire_scan_result(jours_avant_expiration=365))
    resultats = VerificationTls()._analyser_certificat(rapport)

    resultat = _par_identifiant(resultats, "tls_certificat_valide")
    assert resultat is not None
    assert resultat.reussi is True


# --- Protocoles et chiffrements ----------------------------------------------


def test_tls_protocole_obsolete_detecte(monkeypatch):
    """Un protocole TLS 1.0 encore accepté produit tls_protocole_obsolete en gravité élevée."""
    # isinstance() dans le code vise CipherSuitesScanResult : on pointe vers le faux.
    monkeypatch.setattr(tls_module, "CipherSuitesScanResult", FauxResultatChiffrements)
    acceptes = [FauxChiffrementAccepte(FauxChiffrement("TLS_RSA_WITH_AES_128_CBC_SHA"))]
    scan_result = construire_scan_result(tls_1_0=tentative_chiffrements(acceptes))

    resultats = VerificationTls()._analyser_protocoles_et_chiffrements(
        construire_rapport(scan_result)
    )

    resultat = _par_identifiant(resultats, "tls_protocole_obsolete")
    assert resultat is not None
    assert resultat.reussi is False
    assert resultat.gravite is Gravite.ELEVEE
    assert "TLSv1.0" in resultat.details["protocoles"]


def test_tls_chiffrement_faible_detecte(monkeypatch):
    """Un chiffrement RC4 accepté produit tls_chiffrement_faible en gravité élevée."""
    monkeypatch.setattr(tls_module, "CipherSuitesScanResult", FauxResultatChiffrements)
    faible = FauxChiffrementAccepte(FauxChiffrement("TLS_RSA_WITH_RC4_128_SHA", key_size=128))
    scan_result = construire_scan_result(tls_1_2=tentative_chiffrements([faible]))

    resultats = VerificationTls()._analyser_protocoles_et_chiffrements(
        construire_rapport(scan_result)
    )

    resultat = _par_identifiant(resultats, "tls_chiffrement_faible")
    assert resultat is not None
    assert resultat.reussi is False
    assert resultat.gravite is Gravite.ELEVEE


def test_tls_protocoles_sains_renvoie_reussi(monkeypatch):
    """Sans protocole obsolète ni chiffrement faible, on obtient tls_protocoles_sains réussi."""
    monkeypatch.setattr(tls_module, "CipherSuitesScanResult", FauxResultatChiffrements)
    fort = FauxChiffrementAccepte(FauxChiffrement("TLS_AES_256_GCM_SHA384", key_size=256))
    scan_result = construire_scan_result(tls_1_2=tentative_chiffrements([fort]))

    resultats = VerificationTls()._analyser_protocoles_et_chiffrements(
        construire_rapport(scan_result)
    )

    assert _identifiants(resultats) == {"tls_protocoles_sains"}
    assert resultats[0].reussi is True


# --- Redirection HTTP -> HTTPS -----------------------------------------------


@respx.mock
def test_tls_redirection_https_renvoie_reussi(cible_exemple):
    """Une requête HTTP redirigée vers HTTPS produit tls_redirection_https réussi."""
    respx.get("http://exemple.com/").mock(
        return_value=httpx.Response(301, headers={"Location": "https://exemple.com/"})
    )
    respx.get("https://exemple.com/").mock(return_value=httpx.Response(200))

    resultat = asyncio.run(VerificationTls()._verifier_redirection(cible_exemple))

    assert resultat.identifiant == "tls_redirection_https"
    assert resultat.reussi is True


@respx.mock
def test_tls_redirection_absente_renvoie_probleme(cible_exemple):
    """Sans redirection vers HTTPS, on obtient tls_redirection_absente non réussi."""
    respx.get("http://exemple.com/").mock(return_value=httpx.Response(200))

    resultat = asyncio.run(VerificationTls()._verifier_redirection(cible_exemple))

    assert resultat.identifiant == "tls_redirection_absente"
    assert resultat.reussi is False
    assert resultat.gravite is Gravite.MOYENNE


@respx.mock
def test_tls_redirection_indeterminee_si_http_injoignable(cible_exemple):
    """Si le port 80 est injoignable, la redirection est indéterminée sans lever d'exception."""
    respx.get("http://exemple.com/").mock(side_effect=httpx.ConnectError("connexion refusée"))

    resultat = asyncio.run(VerificationTls()._verifier_redirection(cible_exemple))

    assert resultat.identifiant == "tls_redirection_indeterminee"
    assert resultat.reussi is True


# --- Cas limites de executer() ------------------------------------------------


def test_tls_erreur_connexion_ne_leve_pas(monkeypatch, cible_exemple):
    """Si sslyze lève une exception, executer renvoie tls_erreur_connexion sans planter."""

    def _echouer(self, cible):
        raise OSError("hôte inaccessible")

    monkeypatch.setattr(VerificationTls, "_scanner_sslyze", _echouer)

    resultats = asyncio.run(VerificationTls().executer(cible_exemple))

    assert len(resultats) == 1
    assert resultats[0].identifiant == "tls_erreur_connexion"
    assert resultats[0].reussi is False


def test_tls_injoignable_quand_scan_incomplet(monkeypatch, cible_exemple):
    """Un scan non terminé (pas de connectivité) renvoie tls_injoignable."""

    def _rapport_vide(self, cible):
        return construire_rapport(None)

    monkeypatch.setattr(VerificationTls, "_scanner_sslyze", _rapport_vide)

    resultats = asyncio.run(VerificationTls().executer(cible_exemple))

    assert len(resultats) == 1
    assert resultats[0].identifiant == "tls_injoignable"
    assert resultats[0].reussi is False


@respx.mock
def test_tls_executer_cas_sain_agrege_tous_les_resultats(monkeypatch, cible_exemple):
    """Un scan sain complet agrège certificat valide, protocoles sains et redirection HTTPS."""
    monkeypatch.setattr(tls_module, "CipherSuitesScanResult", FauxResultatChiffrements)
    fort = FauxChiffrementAccepte(FauxChiffrement("TLS_AES_256_GCM_SHA384", key_size=256))
    scan_result = construire_scan_result(tls_1_2=tentative_chiffrements([fort]))
    monkeypatch.setattr(
        VerificationTls, "_scanner_sslyze", lambda self, cible: construire_rapport(scan_result)
    )
    respx.get("http://exemple.com/").mock(
        return_value=httpx.Response(301, headers={"Location": "https://exemple.com/"})
    )
    respx.get("https://exemple.com/").mock(return_value=httpx.Response(200))

    resultats = asyncio.run(VerificationTls().executer(cible_exemple))

    identifiants = _identifiants(resultats)
    assert "tls_certificat_valide" in identifiants
    assert "tls_protocoles_sains" in identifiants
    assert "tls_redirection_https" in identifiants
    assert all(r.reussi for r in resultats)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
