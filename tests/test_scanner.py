"""Tests de l'orchestrateur : sélection des vérifications selon le mode de la cible."""

import asyncio

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
    """En mode passif, les deux vérifications TLS et en-têtes (passives) sont retenues."""
    verifications = selectionner_verifications("passif")
    noms = {v.nom for v in verifications}
    assert noms == {"tls", "entetes"}


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
    """scanner() en mode actif exécute aussi bien les checks passifs qu'actifs."""
    monkeypatch.setattr(
        scanner_module, "VERIFICATIONS", [VerificationPassive(), VerificationActive()]
    )
    cible = Cible(domaine="exemple.com", mode="actif")

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
