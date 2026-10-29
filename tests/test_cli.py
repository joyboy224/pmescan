"""Tests de la ligne de commande : version, sorties, garde d'autorisation, codes de sortie.

Aucun réseau : ``scanner`` est toujours remplacé par un faux. Aucun test n'écrit dans le
vrai ``~/.pmescan`` : une fixture automatique pointe ``PMESCAN_DOSSIER`` vers ``tmp_path``.
"""

import io
import json
import os
import subprocess
import sys
from datetime import datetime

import pytest
from typer.testing import CliRunner

import pmescan.cli as cli_module
from pmescan.cli import app
from pmescan.modele import Gravite, Resultat

runner = CliRunner()


@pytest.fixture(autouse=True)
def dossier_journal(monkeypatch, tmp_path):
    """Isole le dossier de pmescan dans tmp_path pour TOUS les tests de ce module.

    Garde-fou : même un test qui oublierait de poser PMESCAN_DOSSIER n'écrirait jamais
    dans le vrai dossier personnel. Renvoie le dossier (non créé à l'avance).
    """
    dossier = tmp_path / "pmescan"
    monkeypatch.setenv("PMESCAN_DOSSIER", str(dossier))
    return dossier


def test_cli_version_affiche_la_version():
    """`pmescan --version` affiche « pmescan 0.1.1 »."""
    resultat = runner.invoke(app, ["--version"])
    assert resultat.exit_code == 0
    assert "pmescan 0.1.1" in resultat.stdout


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

    # Un problème CRITIQUE non réussi : code de sortie 1.
    assert resultat.exit_code == 1
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

    # PDF écrit, mais tls_expire est CRITIQUE : code de sortie 1.
    assert resultat.exit_code == 1
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

    # tls_expire est CRITIQUE : code de sortie 1.
    assert resultat.exit_code == 1
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


def test_cli_verifier_cve_transmis_a_la_cible(monkeypatch, tmp_path):
    """Avec --verifier-cve, la Cible transmise au scanner a verifier_cve=True."""
    # Le mode actif journalise le consentement : jamais dans le vrai ~/.pmescan.
    monkeypatch.setenv("PMESCAN_DOSSIER", str(tmp_path))
    cibles = _capturer_cible(monkeypatch)

    resultat = runner.invoke(
        app,
        [
            "scan",
            "exemple.com",
            "--mode",
            "actif",
            "--jai-l-autorisation",
            "--verifier-cve",
            "--json",
        ],
    )

    assert resultat.exit_code == 0
    assert len(cibles) == 1
    assert cibles[0].verifier_cve is True
    assert cibles[0].domaine == "exemple.com"
    assert cibles[0].mode == "actif"


# --- Garde d'autorisation des modes intrusifs --------------------------------


def _scanner_compteur(monkeypatch, resultats=None) -> list:
    """Remplace le scanner par un faux qui mémorise chaque Cible reçue (compte les appels)."""
    cibles: list = []

    async def _faux_scanner(cible):
        cibles.append(cible)
        return list(resultats or [])

    monkeypatch.setattr(cli_module, "scanner", _faux_scanner)
    return cibles


def _lignes_journal(dossier) -> list[list[str]]:
    """Lit consent.log et renvoie chaque ligne découpée sur les tabulations."""
    contenu = (dossier / "consent.log").read_text(encoding="utf-8")
    return [ligne.split("\t") for ligne in contenu.splitlines()]


def test_cli_mode_invalide_donne_code_2(monkeypatch, dossier_journal):
    """`--mode bidon` est refusé par la validation de l'option : code 2, aucun scan."""
    cibles = _scanner_compteur(monkeypatch)

    resultat = runner.invoke(app, ["scan", "exemple.com", "--mode", "bidon"])

    assert resultat.exit_code == 2
    assert cibles == []
    assert not dossier_journal.exists()


@pytest.mark.parametrize("mode", ["actif", "agressif"])
def test_cli_mode_intrusif_sans_autorisation_refuse(monkeypatch, dossier_journal, mode):
    """Mode intrusif sans --jai-l-autorisation : code 3, message stderr, aucun scan ni journal."""
    cibles = _scanner_compteur(monkeypatch)

    resultat = runner.invoke(app, ["scan", "exemple.com", "--mode", mode])

    assert resultat.exit_code == 3
    # Message en français sur stderr, qui indique comment débloquer la situation.
    assert "--jai-l-autorisation" in resultat.stderr
    assert "Refus" in resultat.stderr
    assert "propriétaire" in resultat.stderr
    assert mode in resultat.stderr
    assert "exemple.com" in resultat.stderr
    assert resultat.stdout == ""
    # Le scanner n'est jamais appelé et rien n'est journalisé.
    assert cibles == []
    assert not (dossier_journal / "consent.log").exists()


@pytest.mark.parametrize("mode", ["actif", "agressif"])
def test_cli_mode_intrusif_autorise_journalise_avant_le_scan(
    monkeypatch, dossier_journal, mode
):
    """Avec le flag : une ligne horodatage/domaine/mode est journalisée AVANT le scan."""
    journal_present_au_scan: list[bool] = []

    async def _faux_scanner(cible):
        journal_present_au_scan.append((dossier_journal / "consent.log").exists())
        return []

    monkeypatch.setattr(cli_module, "scanner", _faux_scanner)

    resultat = runner.invoke(
        app, ["scan", "exemple.com", "--mode", mode, "--jai-l-autorisation"]
    )

    assert resultat.exit_code == 0
    assert journal_present_au_scan == [True]
    lignes = _lignes_journal(dossier_journal)
    assert len(lignes) == 1
    horodatage, domaine, mode_journalise = lignes[0]
    assert domaine == "exemple.com"
    assert mode_journalise == mode
    # Horodatage ISO 8601 parsable et porteur d'un fuseau (UTC).
    instant = datetime.fromisoformat(horodatage)
    assert instant.tzinfo is not None
    assert instant.utcoffset().total_seconds() == 0


def test_cli_deux_scans_autorises_ajoutent_deux_lignes(monkeypatch, dossier_journal):
    """Deux scans autorisés successifs : deux lignes (ajout, pas d'écrasement)."""
    cibles = _scanner_compteur(monkeypatch)

    premier = runner.invoke(
        app, ["scan", "premier.exemple.com", "--mode", "actif", "--jai-l-autorisation"]
    )
    second = runner.invoke(
        app, ["scan", "second.exemple.com", "--mode", "agressif", "--jai-l-autorisation"]
    )

    assert premier.exit_code == 0
    assert second.exit_code == 0
    assert len(cibles) == 2
    lignes = _lignes_journal(dossier_journal)
    assert [(ligne[1], ligne[2]) for ligne in lignes] == [
        ("premier.exemple.com", "actif"),
        ("second.exemple.com", "agressif"),
    ]


def test_cli_passif_avec_flag_ne_journalise_rien(monkeypatch, dossier_journal):
    """Le mode passif n'est pas intrusif : même avec le flag, rien n'est journalisé."""
    cibles = _scanner_compteur(monkeypatch)

    resultat = runner.invoke(app, ["scan", "exemple.com", "--jai-l-autorisation"])

    assert resultat.exit_code == 0
    assert len(cibles) == 1
    assert cibles[0].mode == "passif"
    assert not (dossier_journal / "consent.log").exists()


def test_cli_journal_impossible_dossier_est_un_fichier(monkeypatch, tmp_path):
    """PMESCAN_DOSSIER pointe vers un FICHIER : avertissement stderr, le scan continue."""
    fichier = tmp_path / "pas-un-dossier"
    fichier.write_text("occupé", encoding="utf-8")
    monkeypatch.setenv("PMESCAN_DOSSIER", str(fichier))
    cibles = _scanner_compteur(monkeypatch)

    resultat = runner.invoke(
        app, ["scan", "exemple.com", "--mode", "actif", "--jai-l-autorisation"]
    )

    # Aucun résultat critique : code 0 malgré l'échec du journal.
    assert resultat.exit_code == 0
    assert "Avertissement" in resultat.stderr
    assert "journal de consentement" in resultat.stderr
    assert len(cibles) == 1
    # Le fichier existant n'a pas été altéré.
    assert fichier.read_text(encoding="utf-8") == "occupé"


def test_cli_journal_oserror_scan_continue_code_selon_resultats(monkeypatch):
    """journaliser_consentement lève OSError : avertissement, scan exécuté, code 1 si critique."""

    def _journal_en_panne(domaine, mode):
        raise PermissionError("accès refusé au journal")

    monkeypatch.setattr(cli_module, "journaliser_consentement", _journal_en_panne)
    cibles = _scanner_compteur(
        monkeypatch,
        [Resultat(identifiant="port_ouvert_mysql", gravite=Gravite.CRITIQUE, reussi=False)],
    )

    resultat = runner.invoke(
        app, ["scan", "exemple.com", "--mode", "actif", "--jai-l-autorisation"]
    )

    assert resultat.exit_code == 1
    assert "Avertissement" in resultat.stderr
    assert "accès refusé au journal" in resultat.stderr
    assert len(cibles) == 1
    assert "[PROBLEME] port_ouvert_mysql (critique)" in resultat.stdout


# --- Codes de sortie ---------------------------------------------------------


_SANS_CRITIQUE = [
    Resultat(identifiant="entete_hsts_absent", gravite=Gravite.MOYENNE, reussi=False),
    # Un CRITIQUE réussi n'est pas un problème : il ne doit pas donner le code 1.
    Resultat(identifiant="tls_ok", gravite=Gravite.CRITIQUE, reussi=True),
]
_AVEC_CRITIQUE = [
    Resultat(identifiant="entete_hsts_absent", gravite=Gravite.MOYENNE, reussi=False),
    Resultat(identifiant="tls_expire", gravite=Gravite.CRITIQUE, reussi=False),
]


@pytest.mark.parametrize("options", [[], ["--json"]], ids=["texte", "json"])
@pytest.mark.parametrize(
    ("resultats", "code_attendu"),
    [([], 0), (_SANS_CRITIQUE, 0), (_AVEC_CRITIQUE, 1)],
    ids=["aucun_resultat", "sans_critique", "avec_critique"],
)
def test_cli_code_de_sortie_selon_les_resultats(monkeypatch, options, resultats, code_attendu):
    """Code 0 sans CRITIQUE non réussi, 1 sinon, en sortie texte comme en JSON."""
    _scanner_compteur(monkeypatch, resultats)

    resultat = runner.invoke(app, ["scan", "exemple.com", *options])

    assert resultat.exit_code == code_attendu
    if options == ["--json"]:
        # La sortie reste un JSON valide quel que soit le code.
        assert isinstance(json.loads(resultat.stdout), dict)


def test_cli_pdf_impossible_donne_code_2(monkeypatch, tmp_path):
    """ecrire_pdf lève RuntimeError : message sur stderr et code 2 (erreur)."""
    _scanner_compteur(monkeypatch, _SANS_CRITIQUE)

    def _pdf_en_panne(html, chemin):
        raise RuntimeError("WeasyPrint indisponible")

    monkeypatch.setattr(cli_module, "ecrire_pdf", _pdf_en_panne)

    resultat = runner.invoke(
        app, ["scan", "exemple.com", "--pdf", "--sortie", str(tmp_path / "r.pdf")]
    )

    assert resultat.exit_code == 2
    assert "WeasyPrint indisponible" in resultat.stderr


def test_cli_pdf_reussi_sans_critique_donne_code_0(monkeypatch, tmp_path):
    """PDF écrit et aucun CRITIQUE non réussi : code 0."""
    _scanner_compteur(monkeypatch, _SANS_CRITIQUE)
    monkeypatch.setattr(cli_module, "ecrire_pdf", lambda html, chemin: None)
    chemin = str(tmp_path / "rapport.pdf")

    resultat = runner.invoke(app, ["scan", "exemple.com", "--pdf", "--sortie", chemin])

    assert resultat.exit_code == 0
    assert f"Rapport PDF écrit : {chemin}" in resultat.stdout


# --- CLI -> Cible.autorisation (défense en profondeur) -----------------------


@pytest.mark.parametrize(
    ("options", "attendu"),
    [
        ([], False),
        (["--jai-l-autorisation"], False),  # passif : le flag ne donne aucune autorisation
        (["--mode", "passif", "--jai-l-autorisation"], False),
        (["--mode", "actif", "--jai-l-autorisation"], True),
        (["--mode", "agressif", "--jai-l-autorisation"], True),
    ],
    ids=["passif", "passif_flag", "passif_explicite_flag", "actif_flag", "agressif_flag"],
)
def test_cli_autorisation_transmise_a_la_cible(monkeypatch, dossier_journal, options, attendu):
    """Cible.autorisation vaut True seulement en mode actif/agressif AVEC le flag."""
    cibles = _scanner_compteur(monkeypatch)

    resultat = runner.invoke(app, ["scan", "exemple.com", *options])

    assert resultat.exit_code == 0
    assert len(cibles) == 1
    assert cibles[0].autorisation is attendu


# --- Validation du domaine dans la CLI ---------------------------------------


@pytest.mark.parametrize(
    "domaine",
    ["https://exemple.sn", "exemple.sn:443", "user@exemple.sn", "exemple.sn/chemin", "a..b"],
    ids=["url", "port", "email", "chemin", "label_vide"],
)
def test_cli_domaine_invalide_code_2_sans_scan_ni_journal(
    monkeypatch, dossier_journal, domaine
):
    """Domaine invalide, même en actif autorisé : code 2, message, ni scan ni journal."""
    cibles = _scanner_compteur(monkeypatch)

    resultat = runner.invoke(
        app, ["scan", domaine, "--mode", "actif", "--jai-l-autorisation"]
    )

    assert resultat.exit_code == 2
    assert "n'est pas un nom de domaine valide" in resultat.stderr
    assert "Aucune requête n'a été envoyée" in resultat.stderr
    assert cibles == []
    # La validation précède la garde ET le journal : rien n'est écrit.
    assert not (dossier_journal / "consent.log").exists()


def test_cli_domaine_invalide_neutralise_les_caracteres_de_controle(monkeypatch):
    """Un domaine avec séquence ANSI est refusé et affiché via repr() (pas d'ESC brut)."""
    cibles = _scanner_compteur(monkeypatch)

    resultat = runner.invoke(app, ["scan", "exemple\x1b[31m.sn"])

    assert resultat.exit_code == 2
    assert "\x1b" not in resultat.stderr
    assert "\\x1b" in resultat.stderr
    assert cibles == []


def test_cli_domaine_normalise_dans_la_cible_et_le_journal(monkeypatch, dossier_journal):
    """« EXEMPLE.com. » devient « exemple.com » dans la Cible et dans le journal."""
    cibles = _scanner_compteur(monkeypatch)

    resultat = runner.invoke(
        app, ["scan", "EXEMPLE.com.", "--mode", "actif", "--jai-l-autorisation"]
    )

    assert resultat.exit_code == 0
    assert cibles[0].domaine == "exemple.com"
    assert _lignes_journal(dossier_journal)[0][1] == "exemple.com"


def test_cli_domaine_idn_normalise_dans_le_nom_du_pdf(monkeypatch):
    """« café.fr » : Cible en xn--caf-dma.fr et PDF par défaut rapport-xn--caf-dma.fr.pdf."""
    cibles = _scanner_compteur(monkeypatch)
    appels: dict = {}

    def _faux_ecrire_pdf(html, chemin):
        appels["chemin"] = chemin

    monkeypatch.setattr(cli_module, "ecrire_pdf", _faux_ecrire_pdf)

    resultat = runner.invoke(app, ["scan", "café.fr", "--pdf"])

    assert resultat.exit_code == 0
    assert cibles[0].domaine == "xn--caf-dma.fr"
    assert appels["chemin"] == "rapport-xn--caf-dma.fr.pdf"


# --- Filet d'erreurs : code 2 sans trace Python ------------------------------


def _sans_trace(resultat) -> None:
    """Vérifie qu'aucune trace Python n'apparaît dans les sorties."""
    assert "Traceback" not in resultat.stdout
    assert "Traceback" not in resultat.stderr


def test_cli_pdf_permission_error_donne_code_2(monkeypatch, tmp_path):
    """ecrire_pdf lève PermissionError : message clair sur stderr, code 2, sans trace."""
    _scanner_compteur(monkeypatch, _SANS_CRITIQUE)
    chemin = str(tmp_path / "protege.pdf")

    def _pdf_interdit(html, chemin_pdf):
        raise PermissionError("accès refusé")

    monkeypatch.setattr(cli_module, "ecrire_pdf", _pdf_interdit)

    resultat = runner.invoke(app, ["scan", "exemple.com", "--pdf", "--sortie", chemin])

    assert resultat.exit_code == 2
    assert "impossible d'écrire le rapport PDF" in resultat.stderr
    assert chemin in resultat.stderr
    assert "accès refusé" in resultat.stderr
    _sans_trace(resultat)


def test_cli_exception_imprevue_du_scanner_donne_code_2(monkeypatch):
    """Le scanner lève ZeroDivisionError : message « Erreur inattendue », code 2, sans trace."""

    async def _scanner_casse(cible):
        raise ZeroDivisionError("division par zéro")

    monkeypatch.setattr(cli_module, "scanner", _scanner_casse)

    resultat = runner.invoke(app, ["scan", "exemple.com"])

    assert resultat.exit_code == 2
    assert "Erreur inattendue" in resultat.stderr
    assert "ZeroDivisionError" in resultat.stderr
    assert "division par zéro" in resultat.stderr
    _sans_trace(resultat)


def test_cli_interruption_clavier_donne_code_2(monkeypatch):
    """Le scanner lève KeyboardInterrupt (Ctrl+C) : message d'interruption, code 2."""

    async def _scanner_interrompu(cible):
        raise KeyboardInterrupt

    monkeypatch.setattr(cli_module, "scanner", _scanner_interrompu)

    resultat = runner.invoke(app, ["scan", "exemple.com"])

    assert resultat.exit_code == 2
    assert "Analyse interrompue" in resultat.stderr
    _sans_trace(resultat)


def test_forcer_utf8_reconfigure_un_flux_cp1252(monkeypatch):
    """Un flux en cp1252 (sortie redirigée sous Windows) est repassé en UTF-8."""
    tampon = io.BytesIO()
    flux = io.TextIOWrapper(tampon, encoding="cp1252")
    monkeypatch.setattr(sys, "stdout", flux)

    cli_module._forcer_utf8()
    print("propriétaire", end="")
    flux.flush()

    assert tampon.getvalue() == "propriétaire".encode()


def test_forcer_utf8_ignore_un_flux_sans_reconfigure(monkeypatch):
    """Un flux qui n'est pas un TextIOWrapper (ex. StringIO) est laissé tel quel."""
    flux = io.StringIO()
    monkeypatch.setattr(sys, "stdout", flux)

    cli_module._forcer_utf8()

    assert sys.stdout is flux


def test_cli_sortie_redirigee_reste_en_utf8(dossier_journal):
    """Sortie redirigée avec un encodage local cp1252 : les octets écrits restent UTF-8.

    Reproduit le cas Windows (`pmescan ... > fichier`) sur tout système grâce à
    PYTHONIOENCODING. Le refus du mode agressif sans flag n'envoie aucune requête réseau.
    """
    env = {**os.environ, "PYTHONIOENCODING": "cp1252", "PMESCAN_DOSSIER": str(dossier_journal)}
    env.pop("PYTHONUTF8", None)

    processus = subprocess.run(
        [
            sys.executable,
            "-c",
            "from pmescan.cli import app; app()",
            "scan",
            "exemple.sn",
            "--mode",
            "agressif",
        ],
        capture_output=True,
        env=env,
        timeout=60,
    )

    assert processus.returncode == 3
    assert "propriétaire" in processus.stderr.decode("utf-8")


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
