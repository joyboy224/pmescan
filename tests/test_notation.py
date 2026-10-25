"""Tests du calcul de la note globale (score sur 100 et lettre A–F)."""

import pytest

from pmescan.modele import Gravite, Resultat
from pmescan.notation import calculer_note


def _probleme(gravite: Gravite) -> Resultat:
    """Fabrique un résultat non réussi de la gravité demandée."""
    return Resultat(identifiant="probleme", gravite=gravite, reussi=False)


def _succes(gravite: Gravite = Gravite.INFO) -> Resultat:
    """Fabrique un résultat réussi (ne doit jamais pénaliser)."""
    return Resultat(identifiant="ok", gravite=gravite, reussi=True)


def test_liste_vide_donne_note_maximale():
    """Aucun résultat : score plein 100 et note A."""
    assert calculer_note([]) == (100, "A")


def test_une_critique_retire_quarante_points():
    """Une seule CRITIQUE non réussie -> 100 - 40 = 60 -> note C."""
    score, lettre = calculer_note([_probleme(Gravite.CRITIQUE)])
    assert score == 60
    assert lettre == "C"


def test_critique_et_elevee_donnent_quarante_et_d():
    """Une CRITIQUE (-40) plus une ELEVEE (-20) -> 40 -> note D."""
    resultats = [_probleme(Gravite.CRITIQUE), _probleme(Gravite.ELEVEE)]
    assert calculer_note(resultats) == (40, "D")


def test_les_resultats_reussis_ne_penalisent_pas():
    """Des résultats réussis, même en gravité élevée, ne retirent aucun point."""
    resultats = [
        _succes(Gravite.CRITIQUE),
        _succes(Gravite.ELEVEE),
        _succes(Gravite.MOYENNE),
    ]
    assert calculer_note(resultats) == (100, "A")


def test_score_plancher_a_zero_et_note_f():
    """Plusieurs CRITIQUES ne font jamais descendre le score sous 0 -> note F."""
    resultats = [_probleme(Gravite.CRITIQUE) for _ in range(5)]  # -200 théorique
    score, lettre = calculer_note(resultats)
    assert score == 0
    assert lettre == "F"


def test_gravites_mixtes_cumulent_les_penalites():
    """MOYENNE (-10) + FAIBLE (-3) + INFO (0) -> 87 -> note B."""
    resultats = [
        _probleme(Gravite.MOYENNE),
        _probleme(Gravite.FAIBLE),
        _probleme(Gravite.INFO),
    ]
    score, lettre = calculer_note(resultats)
    assert score == 87
    assert lettre == "B"


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
