"""Calcul de la note globale (score sur 100 et lettre A–F) à partir des résultats."""

from pmescan.modele import Resultat

# Points retirés par problème non résolu, selon sa gravité (voir README.md, « Notation »).
PENALITES: dict[str, int] = {
    "critique": 40,
    "elevee": 20,
    "moyenne": 10,
    "faible": 3,
    "info": 0,
}


def calculer_note(resultats: list[Resultat]) -> tuple[int, str]:
    """Convertit une liste de résultats en (score sur 100, lettre A–F).

    Seuls les résultats non réussis (``reussi=False``) retirent des points. Le
    score est plafonné dans l'intervalle [0, 100].
    """
    score = 100
    for resultat in resultats:
        if not resultat.reussi:
            score -= PENALITES[resultat.gravite.value]
    score = max(0, min(100, score))
    lettre = (
        "A" if score >= 90
        else "B" if score >= 75
        else "C" if score >= 60
        else "D" if score >= 40
        else "E" if score >= 20
        else "F"
    )
    return score, lettre
