"""Tests de la ligne de commande : option --version et sortie --json."""

import json

import pytest
from typer.testing import CliRunner

import pmescan.cli as cli_module
from pmescan.cli import app
from pmescan.modele import Gravite, Resultat

runner = CliRunner()


def test_cli_version_affiche_la_version():
    """`pmescan --version` affiche « pmescan 0.1.0 »."""
    resultat = runner.invoke(app, ["--version"])
    assert resultat.exit_code == 0
    assert "pmescan 0.1.0" in resultat.stdout


def test_cli_scan_json_produit_du_json_valide(monkeypatch):
    """`scan exemple.com --json` produit un JSON valide et sérialisé des résultats."""

    async def _faux_scanner(cible):
        return [
            Resultat(
                identifiant="entete_hsts_absent",
                gravite=Gravite.MOYENNE,
                reussi=False,
                details={"entete": "strict-transport-security"},
            )
        ]

    # On remplace le scanner réseau par un faux pour rester hors-ligne.
    monkeypatch.setattr(cli_module, "scanner", _faux_scanner)

    resultat = runner.invoke(app, ["scan", "exemple.com", "--json"])

    assert resultat.exit_code == 0
    charge = json.loads(resultat.stdout)
    # La CLI renvoie désormais un OBJET agrégé {note, score, resultats}, plus une liste.
    assert isinstance(charge, dict)
    # Une seule MOYENNE non réussie : 100 - 10 = 90 -> note A.
    assert charge["score"] == 90
    assert charge["note"] == "A"
    resultats = charge["resultats"]
    assert isinstance(resultats, list)
    assert resultats[0]["identifiant"] == "entete_hsts_absent"
    assert resultats[0]["gravite"] == "moyenne"
    assert resultats[0]["reussi"] is False


def test_cli_scan_texte_affiche_etat_probleme(monkeypatch):
    """Sans --json, un résultat non réussi s'affiche avec l'état PROBLEME."""

    async def _faux_scanner(cible):
        return [
            Resultat(identifiant="tls_expire", gravite=Gravite.CRITIQUE, reussi=False)
        ]

    monkeypatch.setattr(cli_module, "scanner", _faux_scanner)

    resultat = runner.invoke(app, ["scan", "exemple.com"])

    assert resultat.exit_code == 0
    assert "[PROBLEME] tls_expire (critique)" in resultat.stdout


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
