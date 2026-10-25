"""Tests hors-ligne du rapport PDF : contexte, rendu HTML et génération PDF.

Rappel d'architecture (voir generateur.py) :

- ``construire_contexte`` et ``rendre_html`` sont du Python pur : ils n'importent
  AUCUNE bibliothèque native et se testent donc sans WeasyPrint ;
- ``ecrire_pdf`` est la seule fonction à importer WeasyPrint, et le fait
  localement.

Sur cette machine Windows, WeasyPrint est installé mais ses bibliothèques
système (GTK/Pango/Cairo) sont absentes : ``import weasyprint`` lève une OSError.
On gère cela de deux façons complémentaires :

1. un test qui SIMULE l'absence de WeasyPrint (en neutralisant son import) et
   vérifie que ``ecrire_pdf`` lève un RuntimeError au message français ;
2. un test de production d'un vrai PDF, protégé par ``_weasyprint_disponible()``
   qui tente l'import complet et attrape à la fois ImportError ET OSError (car
   l'absence des libs natives se manifeste par une OSError, que le simple
   ``pytest.importorskip`` ne saurait pas ignorer).

Aucun test ne touche au réseau ni ne dépend des libs natives pour réussir.
"""

import sys

import pytest

from pmescan.modele import Cible, Gravite, Resultat
from pmescan.rapport.generateur import (
    construire_contexte,
    ecrire_pdf,
    rendre_html,
)


def _weasyprint_disponible() -> bool:
    """Indique si WeasyPrint s'importe réellement (libs natives comprises).

    On tente l'import complet ``from weasyprint import HTML`` et on attrape
    ImportError comme OSError : sur une machine sans GTK/Pango, l'import lève une
    OSError, que ``pytest.importorskip`` ne saurait pas ignorer.
    """
    try:
        from weasyprint import HTML  # noqa: F401
    except (ImportError, OSError):
        return False
    return True


# --- Jeu de résultats varié partagé -----------------------------------------


def _cible() -> Cible:
    """Cible passive standard pour les tests."""
    return Cible(domaine="exemple.com", mode="passif")


def _resultats_varies() -> list[Resultat]:
    """Une CRITIQUE, une ELEVEE, une MOYENNE, une INFO non réussie, une réussie.

    L'ordre d'insertion est volontairement DÉSORDONNÉ (moyenne avant critique)
    pour prouver que ``construire_contexte`` trie bien par gravité.
    """
    return [
        Resultat(identifiant="entete_hsts_absent", gravite=Gravite.MOYENNE, reussi=False,
                 preuve="aucun en-tête HSTS"),
        Resultat(identifiant="tls_expire", gravite=Gravite.CRITIQUE, reussi=False,
                 preuve="expiré depuis 5 jours"),
        Resultat(identifiant="spf_absent", gravite=Gravite.ELEVEE, reussi=False,
                 preuve="aucun enregistrement SPF"),
        # INFO non réussie : diagnostic, doit rester HORS des fiches mais DANS l'annexe.
        Resultat(identifiant="dkim_absent", gravite=Gravite.INFO, reussi=False,
                 preuve="sélecteurs courants testés sans succès"),
        # Résultat réussi : doit rester HORS des fiches mais DANS l'annexe.
        Resultat(identifiant="dmarc_absent", gravite=Gravite.ELEVEE, reussi=True,
                 preuve="DMARC présent"),
    ]


# --- construire_contexte -----------------------------------------------------


def test_contexte_fiches_excluent_info_et_reussis():
    """Les fiches ne contiennent que les problèmes non réussis et hors INFO."""
    contexte = construire_contexte(_cible(), _resultats_varies(), note="C", score=55)
    identifiants_fiches = [fiche["identifiant"] for fiche in contexte["fiches"]]
    # Trois problèmes présentables : critique, élevée, moyenne.
    assert identifiants_fiches == ["tls_expire", "spf_absent", "entete_hsts_absent"]
    # L'INFO non réussie et le résultat réussi sont bien exclus des fiches.
    assert "dkim_absent" not in identifiants_fiches
    assert "dmarc_absent" not in identifiants_fiches
    assert contexte["nombre_problemes"] == 3


def test_contexte_problemes_tries_par_gravite():
    """Les fiches sont triées de la plus urgente (critique) à la moins urgente."""
    contexte = construire_contexte(_cible(), _resultats_varies(), note="C", score=55)
    gravites = [fiche["gravite"] for fiche in contexte["fiches"]]
    assert gravites == ["critique", "elevee", "moyenne"]


def test_contexte_actions_urgentes_au_plus_trois_et_dans_lordre():
    """actions_urgentes garde au plus 3 problèmes, dans l'ordre de gravité.

    On fournit ici CINQ problèmes pour prouver l'écrêtage à 3, en plus de l'ordre.
    """
    resultats = [
        Resultat(identifiant="entete_csp_absent", gravite=Gravite.MOYENNE, reussi=False),
        Resultat(identifiant="tls_expire", gravite=Gravite.CRITIQUE, reussi=False),
        Resultat(identifiant="fichier_expose_env", gravite=Gravite.CRITIQUE, reussi=False),
        Resultat(identifiant="spf_absent", gravite=Gravite.ELEVEE, reussi=False),
        Resultat(identifiant="dnssec_absent", gravite=Gravite.FAIBLE, reussi=False),
    ]
    contexte = construire_contexte(_cible(), resultats, note="E", score=20)
    urgentes = contexte["actions_urgentes"]
    assert len(urgentes) == 3
    # Les deux critiques d'abord, puis l'élevée ; la moyenne et la faible sont écartées.
    assert [fiche["gravite"] for fiche in urgentes] == ["critique", "critique", "elevee"]
    assert {fiche["identifiant"] for fiche in urgentes} == {
        "tls_expire", "fichier_expose_env", "spf_absent"
    }


def test_contexte_compteurs_par_gravite_corrects():
    """par_gravite compte les PROBLÈMES (non réussis, hors INFO) par niveau."""
    contexte = construire_contexte(_cible(), _resultats_varies(), note="C", score=55)
    par_gravite = contexte["par_gravite"]
    assert par_gravite == {
        "critique": 1,
        "elevee": 1,
        "moyenne": 1,
        "faible": 0,
        # L'INFO non réussie n'est pas comptée comme un problème.
        "info": 0,
    }


def test_contexte_annexe_contient_tous_les_resultats():
    """L'annexe technique liste TOUS les résultats, INFO et réussis compris."""
    resultats = _resultats_varies()
    contexte = construire_contexte(_cible(), resultats, note="C", score=55)
    annexe = contexte["annexe"]
    assert len(annexe) == len(resultats)
    identifiants_annexe = [ligne["identifiant"] for ligne in annexe]
    assert identifiants_annexe == [r.identifiant for r in resultats]
    # L'INFO non réussie et le résultat réussi figurent bien dans l'annexe.
    assert "dkim_absent" in identifiants_annexe
    assert "dmarc_absent" in identifiants_annexe
    # L'état réussi/non réussi est conservé tel quel.
    ligne_dmarc = next(ligne for ligne in annexe if ligne["identifiant"] == "dmarc_absent")
    assert ligne_dmarc["reussi"] is True


def test_contexte_textes_viennent_de_fr_yaml():
    """Le titre d'une fiche provient bien de fr.yaml (ex. tls_expire)."""
    contexte = construire_contexte(_cible(), _resultats_varies(), note="C", score=55)
    fiche_tls = next(f for f in contexte["fiches"] if f["identifiant"] == "tls_expire")
    # Titre exact défini dans pmescan/i18n/fr.yaml pour tls_expire.
    assert fiche_tls["titre"] == "Certificat de sécurité expiré"
    assert fiche_tls["qui_corrige"] == "hebergeur"
    # Le risque et l'action sont repris et non vides.
    assert fiche_tls["risque"]
    assert fiche_tls["action"]


# --- rendre_html -------------------------------------------------------------


def test_rendre_html_contient_les_elements_cles():
    """Le HTML rendu est une chaîne non vide portant les éléments clés du rapport.

    Ce test N'IMPORTE PAS WeasyPrint : rendre_html est du Python pur.
    """
    contexte = construire_contexte(_cible(), _resultats_varies(), note="C", score=55)
    html = rendre_html(contexte)

    assert isinstance(html, str)
    assert html.strip()
    # Nom du domaine et note présents.
    assert "exemple.com" in html
    assert "C" in html
    # Libellés de structure du gabarit.
    assert "Actions urgentes" in html
    assert "Rappel légal" in html
    # Mention de la loi 2008-12 et de la CDP (rappel légal sénégalais).
    assert "2008-12" in html
    assert "CDP" in html
    # Titre d'au moins un problème, issu de fr.yaml.
    assert "Certificat de sécurité expiré" in html


def test_rendre_html_ne_depend_pas_de_weasyprint(monkeypatch):
    """rendre_html fonctionne même si WeasyPrint est totalement indisponible."""
    # On neutralise l'import de weasyprint : s'il était sollicité, l'appel casserait.
    monkeypatch.setitem(sys.modules, "weasyprint", None)
    contexte = construire_contexte(_cible(), _resultats_varies(), note="C", score=55)
    html = rendre_html(contexte)
    assert "exemple.com" in html


# --- ecrire_pdf --------------------------------------------------------------


def test_ecrire_pdf_sans_libs_natives_leve_runtimeerror(monkeypatch, tmp_path):
    """Sans WeasyPrint importable, ecrire_pdf lève un RuntimeError en français.

    On force l'échec de l'import local ``from weasyprint import HTML`` en plaçant
    None dans sys.modules : ``import weasyprint`` lève alors ImportError, cas que
    ecrire_pdf doit convertir en RuntimeError explicite pour l'utilisateur.
    """
    monkeypatch.setitem(sys.modules, "weasyprint", None)
    chemin = tmp_path / "rapport.pdf"

    with pytest.raises(RuntimeError) as info:
        ecrire_pdf("<html></html>", str(chemin))

    message = str(info.value)
    assert "PDF" in message
    assert "WeasyPrint" in message
    # Message bien en français (vocabulaire métier attendu).
    assert "génération" in message.lower()
    # Aucun fichier ne doit avoir été écrit.
    assert not chemin.exists()


@pytest.mark.skipif(
    not _weasyprint_disponible(),
    reason="WeasyPrint ou ses bibliothèques natives (GTK/Pango) sont absentes.",
)
def test_ecrire_pdf_produit_un_vrai_pdf(tmp_path):
    """Si WeasyPrint est pleinement disponible, ecrire_pdf écrit un vrai PDF.

    Test automatiquement ignoré sur cette machine (libs natives absentes).
    """
    contexte = construire_contexte(_cible(), _resultats_varies(), note="C", score=55)
    html = rendre_html(contexte)
    chemin = tmp_path / "rapport.pdf"

    ecrire_pdf(html, str(chemin))

    assert chemin.exists()
    assert chemin.read_bytes().startswith(b"%PDF")


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
