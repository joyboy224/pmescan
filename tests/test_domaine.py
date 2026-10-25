"""Tests unitaires de la validation et de la normalisation du domaine (pmescan.domaine)."""

import pytest

from pmescan.domaine import DomaineInvalide, valider_domaine

# Nom de 253 caractères exactement (limite RFC 1035) : 3 labels de 63 + 1 de 61 + 3 points.
_NOM_253 = "a" * 63 + "." + "b" * 63 + "." + "c" * 63 + "." + "d" * 61
# Un caractère de trop : 254.
_NOM_254 = "a" * 63 + "." + "b" * 63 + "." + "c" * 63 + "." + "d" * 62


# --- Cas acceptés ------------------------------------------------------------


@pytest.mark.parametrize(
    ("saisie", "attendu"),
    [
        ("exemple.sn", "exemple.sn"),
        ("EXEMPLE.com.", "exemple.com"),  # minuscules + point final retiré
        ("www.boutique.exemple.sn", "www.boutique.exemple.sn"),  # sous-domaines
        ("mon-site.exemple.sn", "mon-site.exemple.sn"),  # tiret interne autorisé
        ("café.fr", "xn--caf-dma.fr"),  # IDN converti en forme ASCII
        ("a" * 63 + ".com", "a" * 63 + ".com"),  # label de 63 caractères
        (_NOM_253, _NOM_253),  # total de 253 caractères
        (_NOM_253 + ".", _NOM_253),  # 253 + point final toléré
    ],
    ids=[
        "simple",
        "majuscules_point_final",
        "sous_domaines",
        "tiret_interne",
        "idn",
        "label_63",
        "total_253",
        "total_253_point_final",
    ],
)
def test_valider_domaine_accepte_et_normalise(saisie, attendu):
    """Les noms d'hôte valides sont acceptés et renvoyés sous forme normalisée."""
    assert valider_domaine(saisie) == attendu


# --- Cas refusés -------------------------------------------------------------


@pytest.mark.parametrize(
    "saisie",
    [
        "",
        ".",
        "https://exemple.sn",
        "user@exemple.sn",
        "exemple.sn/chemin",
        "exemple.sn:443",
        "exemple .sn",
        " exemple.sn",
        "-exemple.sn",
        "exemple-.sn",
        "www.-exemple.sn",
        "a" * 64 + ".com",
        _NOM_254,
        "a..b",
        ".exemple.sn",
        "exemple.sn..",
        "exemple_test.sn",
        "exemple\x00.sn",
        "exemple\x1b[31m.sn",
        "exemple\n.sn",
        "exemple.sn?x=1",
        "exemple.sn#ancre",
    ],
    ids=[
        "vide",
        "point_seul",
        "schema_https",
        "adresse_email",
        "chemin",
        "port",
        "espace",
        "espace_initial",
        "tiret_debut_label",
        "tiret_fin_label",
        "tiret_debut_sous_label",
        "label_64",
        "total_254",
        "label_vide",
        "point_initial",
        "deux_points_finaux",
        "tiret_bas",
        "caractere_nul",
        "sequence_ansi",
        "retour_ligne",
        "requete",
        "ancre",
    ],
)
def test_valider_domaine_refuse(saisie):
    """URL, e-mail, port, chemin, espaces, labels mal formés ou trop longs sont refusés."""
    with pytest.raises(DomaineInvalide):
        valider_domaine(saisie)


# --- IDNA 2008 / UTS 46 non transitionnel ------------------------------------
# Les caractères non ASCII sont écrits en séquences d'échappement pour éviter toute
# confusion visuelle (homoglyphes) dans le source.


@pytest.mark.parametrize(
    ("saisie", "attendu"),
    [
        # « faß.de » : le ß est CONSERVÉ (non transitionnel). IDNA 2003 donnerait
        # « fass.de », qui est un AUTRE domaine.
        ("faß.de", "xn--fa-hia.de"),
        # « βόλος.gr » : le sigma final ς est conservé (valeur figée, paquet idna 3.x).
        ("βόλος.gr", "xn--nxasmm1c.gr"),
        # « ΒΌΛΟΣ.gr » en capitales : Σ se replie en σ (sigma non final).
        ("ΒΌΛΟΣ.gr", "xn--nxasmq6b.gr"),
        # Pleine chasse « ＥＸＥＭＰＬＥ.com » : normalisée en ASCII minuscule.
        ("ＥＸＥＭＰＬＥ.com", "exemple.com"),
    ],
    ids=["eszett", "sigma_final", "sigma_capitale", "pleine_chasse"],
)
def test_valider_domaine_uts46_non_transitionnel(saisie, attendu):
    """Les IDN sont encodés en UTS 46 non transitionnel (ß et ς conservés)."""
    assert valider_domaine(saisie) == attendu


@pytest.mark.parametrize(
    "saisie",
    ["faß.de", "βόλος.gr"],
    ids=["eszett", "sigma_final"],
)
def test_valider_domaine_differe_du_codec_idna_2003(saisie):
    """Non-régression : le résultat n'est PAS celui du codec « idna » de Python (IDNA 2003)."""
    forme_2003 = saisie.encode("idna").decode("ascii")
    assert valider_domaine(saisie) != forme_2003


# --- Formes numériques -------------------------------------------------------


@pytest.mark.parametrize(
    "saisie",
    ["1.2.3.4", "123.exemple.com"],
    ids=["ipv4_canonique", "label_numerique_non_final"],
)
def test_valider_domaine_accepte_formes_numeriques_canoniques(saisie):
    """IPv4 canonique et label numérique hors dernière position sont acceptés tels quels."""
    assert valider_domaine(saisie) == saisie


@pytest.mark.parametrize(
    "saisie",
    [
        "2130706433",
        "127.1",
        "0x7f.1",
        "999",
        "01.2.3.4",
        "1.2.3.4.5",
        "256.1.1.1",
        "exemple.123",
    ],
    ids=[
        "entier_decimal",
        "ipv4_abregee",
        "hexadecimal",
        "nombre_seul",
        "zero_initial",
        "cinq_octets",
        "octet_hors_borne",
        "tld_numerique",
    ],
)
def test_valider_domaine_refuse_formes_numeriques_ambigues(saisie):
    """Formes que certains résolveurs prennent pour une adresse IP : refusées."""
    with pytest.raises(DomaineInvalide):
        valider_domaine(saisie)


def test_domaine_invalide_est_une_value_error():
    """DomaineInvalide hérite de ValueError (capturable par les appelants génériques)."""
    assert issubclass(DomaineInvalide, ValueError)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
