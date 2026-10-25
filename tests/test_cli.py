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


def _faux_scanner_tls_expire():
    """Fabrique un faux scanner asynchrone renvoyant un unique problème critique."""

    async def _faux_scanner(cible):
        return [
            Resultat(identifiant="tls_expire", gravite=Gravite.CRITIQUE, reussi=False)
        ]

    return _faux_scanner


def test_cli_scan_pdf_appelle_la_chaine_avec_sortie_par_defaut(monkeypatch):
    """`scan exemple.com --pdf` enchaîne contexte->html->pdf vers rapport-<domaine>.pdf.

    On remplace `scanner` (pas de réseau) ET `ecrire_pdf` (pas de lib native) par
    des faux ; WeasyPrint n'est jamais sollicité.
    """
    monkeypatch.setattr(cli_module, "scanner", _faux_scanner_tls_expire())

    appels = {}

    def _faux_ecrire_pdf(html, chemin):
        # On mémorise ce que la CLI a construit pour vérifier la chaîne complète.
        appels["html"] = html
        appels["chemin"] = chemin

    monkeypatch.setattr(cli_module, "ecrire_pdf", _faux_ecrire_pdf)

    resultat = runner.invoke(app, ["scan", "exemple.com", "--pdf"])

    assert resultat.exit_code == 0
    # Chemin par défaut : rapport-<domaine>.pdf.
    assert appels["chemin"] == "rapport-exemple.com.pdf"
    # Le HTML passé à ecrire_pdf vient bien de la chaîne construire_contexte->rendre_html.
    assert "exemple.com" in appels["html"]
    assert "Certificat de sécurité expiré" in appels["html"]
    # La CLI affiche le chemin du rapport écrit.
    assert "rapport-exemple.com.pdf" in resultat.stdout


def test_cli_scan_pdf_respecte_option_sortie(monkeypatch, tmp_path):
    """L'option --sortie impose le chemin du PDF écrit et affiché."""
    monkeypatch.setattr(cli_module, "scanner", _faux_scanner_tls_expire())

    appels = {}

    def _faux_ecrire_pdf(html, chemin):
        appels["chemin"] = chemin

    monkeypatch.setattr(cli_module, "ecrire_pdf", _faux_ecrire_pdf)

    chemin_voulu = str(tmp_path / "mon-rapport.pdf")
    resultat = runner.invoke(
        app, ["scan", "exemple.com", "--pdf", "--sortie", chemin_voulu]
    )

    assert resultat.exit_code == 0
    assert appels["chemin"] == chemin_voulu
    assert chemin_voulu in resultat.stdout


# --- Option --verifier-cve (opt-in OSV) --------------------------------------


def _capturer_cible(monkeypatch) -> list:
    """Remplace le scanner par un faux qui mémorise la Cible reçue (aucun réseau)."""
    cibles: list = []

    async def _faux_scanner(cible):
        cibles.append(cible)
        return []

    monkeypatch.setattr(cli_module, "scanner", _faux_scanner)
    return cibles


def test_cli_verifier_cve_desactive_par_defaut(monkeypatch):
    """Sans --verifier-cve, la Cible transmise au scanner a verifier_cve=False."""
    cibles = _capturer_cible(monkeypatch)

    resultat = runner.invoke(app, ["scan", "exemple.com", "--json"])

    assert resultat.exit_code == 0
    assert len(cibles) == 1
    assert cibles[0].verifier_cve is False


def test_cli_verifier_cve_transmis_a_la_cible(monkeypatch):
    """Avec --verifier-cve, la Cible transmise au scanner a verifier_cve=True."""
    cibles = _capturer_cible(monkeypatch)

    resultat = runner.invoke(
        app, ["scan", "exemple.com", "--mode", "actif", "--verifier-cve", "--json"]
    )

    assert resultat.exit_code == 0
    assert len(cibles) == 1
    assert cibles[0].verifier_cve is True
    assert cibles[0].domaine == "exemple.com"
    assert cibles[0].mode == "actif"


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
