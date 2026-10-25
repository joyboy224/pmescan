"""Tests unitaires de la garde d'autorisation et du journal de consentement.

Aucun test n'écrit dans le vrai dossier personnel : ``PMESCAN_DOSSIER`` pointe toujours
vers ``tmp_path``, et ``Path.home`` est remplacé quand on teste la valeur par défaut.
"""

from datetime import datetime
from pathlib import Path

import pytest

from pmescan.autorisation import (
    MODES_INTRUSIFS,
    NOM_JOURNAL,
    VARIABLE_DOSSIER,
    ModeScan,
    _nettoyer_champ,
    dossier_pmescan,
    exige_autorisation,
    journaliser_consentement,
)


@pytest.fixture(autouse=True)
def dossier_isole(monkeypatch, tmp_path):
    """Garde-fou : PMESCAN_DOSSIER pointe vers tmp_path pour tous les tests du module."""
    dossier = tmp_path / "pmescan"
    monkeypatch.setenv(VARIABLE_DOSSIER, str(dossier))
    return dossier


# --- exige_autorisation ------------------------------------------------------


@pytest.mark.parametrize(
    ("mode", "attendu"),
    [(ModeScan.PASSIF, False), (ModeScan.ACTIF, True), (ModeScan.AGRESSIF, True)],
    ids=["passif", "actif", "agressif"],
)
def test_exige_autorisation_par_mode(mode, attendu):
    """Seuls les modes actif et agressif exigent --jai-l-autorisation."""
    assert exige_autorisation(mode) is attendu


def test_modes_intrusifs_sont_actif_et_agressif():
    """La liste des modes intrusifs est exactement {actif, agressif}."""
    assert frozenset({ModeScan.ACTIF, ModeScan.AGRESSIF}) == MODES_INTRUSIFS


def test_valeurs_du_mode_de_scan():
    """Les valeurs de ModeScan sont celles attendues par Cible.mode."""
    assert [mode.value for mode in ModeScan] == ["passif", "actif", "agressif"]


# --- dossier_pmescan ---------------------------------------------------------


def test_dossier_pmescan_respecte_la_variable(monkeypatch, tmp_path):
    """PMESCAN_DOSSIER définie : c'est ce dossier qui est utilisé."""
    voulu = tmp_path / "ailleurs"
    monkeypatch.setenv(VARIABLE_DOSSIER, str(voulu))

    assert dossier_pmescan() == voulu


@pytest.mark.parametrize("valeur", [None, ""], ids=["absente", "vide"])
def test_dossier_pmescan_par_defaut_dans_home(monkeypatch, tmp_path, valeur):
    """Variable absente ou vide : ~/.pmescan (home remplacé par tmp_path)."""
    if valeur is None:
        monkeypatch.delenv(VARIABLE_DOSSIER, raising=False)
    else:
        monkeypatch.setenv(VARIABLE_DOSSIER, valeur)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))

    assert dossier_pmescan() == tmp_path / ".pmescan"


# --- journaliser_consentement ------------------------------------------------


def test_journal_cree_le_dossier_et_ecrit_une_ligne(dossier_isole):
    """Le dossier est créé au besoin ; la ligne est « horodatage UTC, domaine, mode »."""
    assert not dossier_isole.exists()

    chemin = journaliser_consentement("exemple.com", ModeScan.ACTIF)

    assert chemin == dossier_isole / NOM_JOURNAL
    lignes = chemin.read_text(encoding="utf-8").splitlines()
    assert len(lignes) == 1
    horodatage, domaine, mode = lignes[0].split("\t")
    assert domaine == "exemple.com"
    assert mode == "actif"
    instant = datetime.fromisoformat(horodatage)
    assert instant.utcoffset().total_seconds() == 0


def test_journal_ajoute_sans_ecraser(dossier_isole):
    """Deux appels ajoutent deux lignes dans l'ordre."""
    journaliser_consentement("un.exemple.com", ModeScan.ACTIF)
    chemin = journaliser_consentement("deux.exemple.com", ModeScan.AGRESSIF)

    lignes = [ligne.split("\t") for ligne in chemin.read_text(encoding="utf-8").splitlines()]
    assert [(ligne[1], ligne[2]) for ligne in lignes] == [
        ("un.exemple.com", "actif"),
        ("deux.exemple.com", "agressif"),
    ]


def test_journal_nettoie_tabulations_et_retours_a_la_ligne(dossier_isole):
    """Un domaine piégé (\\t, \\r, \\n) ne casse pas le format : une ligne, trois champs."""
    chemin = journaliser_consentement("exe\tmple.com\r\nfaux\tligne", ModeScan.ACTIF)

    contenu = chemin.read_text(encoding="utf-8")
    assert "\r" not in contenu
    lignes = contenu.splitlines()
    assert len(lignes) == 1
    champs = lignes[0].split("\t")
    assert len(champs) == 3
    assert champs[1] == "exe mple.com  faux ligne"
    assert champs[2] == "actif"


@pytest.mark.parametrize(
    "caractere",
    ["\x0b", "\x0c", "\x85", " ", " ", "\x1b", "\t", "\r", "\n", "\x00"],
    ids=["VT", "FF", "NEL", "LS", "PS", "ESC", "TAB", "CR", "LF", "NUL"],
)
def test_nettoyer_champ_remplace_les_non_imprimables(caractere):
    """Chaque caractère non imprimable (sauts de ligne Unicode, ESC…) devient une espace."""
    assert _nettoyer_champ(f"a{caractere}b") == "a b"


def test_nettoyer_champ_neutralise_une_sequence_ansi():
    """« \\x1b[31m » : l'ESC est remplacé, la séquence ne peut plus colorer le terminal."""
    assert _nettoyer_champ("rouge\x1b[31mtexte") == "rouge [31mtexte"


def test_nettoyer_champ_conserve_le_texte_imprimable():
    """Le texte imprimable (y compris accents et IDN) est conservé tel quel."""
    assert _nettoyer_champ("café.fr xn--caf-dma.fr") == "café.fr xn--caf-dma.fr"


def test_journal_reste_une_ligne_avec_separateurs_unicode(dossier_isole):
    """Domaine piégé (VT, FF, NEL, LS, PS, ANSI) : une seule ligne, trois champs.

    ``str.splitlines()`` coupe aussi sur \\x0b, \\x0c, \\x85, U+2028 et U+2029 : c'est
    donc lui qu'on utilise pour prouver que le journal n'est pas falsifiable.
    """
    domaine = "a\x0bb\x0cc\x85d e f\x1b[31mg"

    chemin = journaliser_consentement(domaine, ModeScan.AGRESSIF)

    contenu = chemin.read_text(encoding="utf-8")
    lignes = contenu.splitlines()
    assert len(lignes) == 1
    champs = lignes[0].split("\t")
    assert len(champs) == 3
    assert champs[1] == "a b c d e f [31mg"
    assert champs[2] == "agressif"
    assert "\x1b" not in contenu


def test_journal_leve_oserror_si_dossier_est_un_fichier(monkeypatch, tmp_path):
    """Le dossier est en fait un fichier : OSError remonte (l'appelant décide)."""
    fichier = tmp_path / "fichier"
    fichier.write_text("x", encoding="utf-8")
    monkeypatch.setenv(VARIABLE_DOSSIER, str(fichier))

    with pytest.raises(OSError):
        journaliser_consentement("exemple.com", ModeScan.ACTIF)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
