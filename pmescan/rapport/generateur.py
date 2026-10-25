"""Construction du contexte, rendu HTML (pur) et génération PDF (WeasyPrint).

La logique est volontairement scindée en trois fonctions :

- :func:`construire_contexte` agrège les données du scan (pure logique) ;
- :func:`rendre_html` transforme ce contexte en HTML via Jinja2 (pur Python,
  aucune dépendance native, donc testable sans WeasyPrint) ;
- :func:`ecrire_pdf` convertit ce HTML en PDF ; elle est la *seule* à importer
  WeasyPrint, et le fait localement pour que le reste du module reste importable
  même si les bibliothèques système GTK/Pango manquent.

Aucun texte vulgarisé n'est écrit en dur ici : il provient tout entier de
``i18n/fr.yaml`` (via les identifiants) et des libellés de structure du gabarit.
"""

import importlib.resources
from datetime import datetime
from typing import Any

from jinja2 import Environment, select_autoescape

from pmescan.i18n import charger_textes
from pmescan.modele import Cible, Gravite, Resultat

# Rang de tri des gravités, de la plus urgente (0) à la moins urgente.
_RANG_GRAVITE: dict[Gravite, int] = {
    Gravite.CRITIQUE: 0,
    Gravite.ELEVEE: 1,
    Gravite.MOYENNE: 2,
    Gravite.FAIBLE: 3,
    Gravite.INFO: 4,
}

# Noms de mois en français pour la date du scan (mise en forme, pas de l'i18n métier).
_MOIS_FR: tuple[str, ...] = (
    "janvier", "février", "mars", "avril", "mai", "juin",
    "juillet", "août", "septembre", "octobre", "novembre", "décembre",
)

# Nombre d'actions mises en avant sur la page de garde.
_NB_ACTIONS_URGENTES = 3


def _dater(moment: datetime) -> str:
    """Met en forme une date en français clair, ex. « 25 octobre 2026 à 14:30 »."""
    return f"{moment.day} {_MOIS_FR[moment.month - 1]} {moment.year} à {moment:%H:%M}"


def _textes_identifiant(textes: dict[str, Any], identifiant: str) -> dict[str, str]:
    """Renvoie les textes vulgarisés d'un identifiant, avec repli si absent."""
    entree = textes.get(identifiant)
    if not isinstance(entree, dict):
        # Aucun texte connu pour cet identifiant : on affiche au moins l'identifiant brut.
        return {
            "titre": identifiant,
            "risque": "",
            "qui_corrige": "",
            "effort": "",
            "action": "",
        }
    return {
        "titre": str(entree.get("titre", identifiant)),
        "risque": str(entree.get("risque", "")).strip(),
        "qui_corrige": str(entree.get("qui_corrige", "")),
        "effort": str(entree.get("effort", "")),
        "action": str(entree.get("action", "")).strip(),
    }


def construire_contexte(
    cible: Cible,
    resultats: list[Resultat],
    note: str,
    score: int,
    langue: str = "fr",
) -> dict[str, Any]:
    """Agrège tout ce dont le gabarit a besoin à partir des résultats du scan.

    Cette fonction est de la logique pure : elle ne dépend d'aucune bibliothèque
    native et peut être testée seule. Elle regroupe les résultats par gravité,
    calcule les trois actions les plus urgentes, charge les textes de ``fr.yaml``
    et prépare les compteurs du résumé.
    """
    textes = charger_textes(langue)

    # Problèmes à présenter en fiches : non réussis et hors diagnostic (INFO).
    problemes = [
        resultat
        for resultat in resultats
        if not resultat.reussi and resultat.gravite is not Gravite.INFO
    ]
    problemes.sort(key=lambda resultat: _RANG_GRAVITE[resultat.gravite])

    fiches: list[dict[str, Any]] = []
    for resultat in problemes:
        fiche = _textes_identifiant(textes, resultat.identifiant)
        fiche["identifiant"] = resultat.identifiant
        fiche["gravite"] = resultat.gravite.value
        fiche["preuve"] = resultat.preuve
        fiches.append(fiche)

    # Compteurs de problèmes par gravité (pour le résumé rédigé dans le gabarit).
    par_gravite: dict[str, int] = {gravite.value: 0 for gravite in Gravite}
    for resultat in problemes:
        par_gravite[resultat.gravite.value] += 1

    # Annexe technique : tous les résultats bruts, avec leur preuve.
    annexe = [
        {
            "identifiant": resultat.identifiant,
            "gravite": resultat.gravite.value,
            "reussi": resultat.reussi,
            "preuve": resultat.preuve,
        }
        for resultat in resultats
    ]

    return {
        "domaine": cible.domaine,
        "mode": cible.mode,
        "date_scan": _dater(datetime.now()),
        "note": note,
        "score": score,
        "fiches": fiches,
        "actions_urgentes": fiches[:_NB_ACTIONS_URGENTES],
        "par_gravite": par_gravite,
        "nombre_problemes": len(problemes),
        "annexe": annexe,
    }


def rendre_html(contexte: dict[str, Any]) -> str:
    """Rend le gabarit Jinja2 ``modele.html`` en chaîne HTML.

    Pur Python : n'importe aucune bibliothèque native et reste donc utilisable
    (et testable) même lorsque WeasyPrint n'est pas installable.
    """
    gabarit = (
        importlib.resources.files("pmescan.rapport")
        .joinpath("modele.html")
        .read_text(encoding="utf-8")
    )
    environnement = Environment(autoescape=select_autoescape(["html", "xml"]))
    return environnement.from_string(gabarit).render(**contexte)


def ecrire_pdf(html: str, chemin_sortie: str) -> None:
    """Convertit le HTML du rapport en PDF via WeasyPrint et l'écrit sur disque.

    Seule fonction du module à dépendre de WeasyPrint. L'import est local afin
    que :func:`construire_contexte` et :func:`rendre_html` restent importables
    même si les bibliothèques système (GTK/Pango) de WeasyPrint sont absentes.
    """
    try:
        from weasyprint import HTML  # import local volontaire (voir docstring)
    except (ImportError, OSError) as erreur:
        raise RuntimeError(
            "La génération du PDF nécessite WeasyPrint et ses bibliothèques "
            "système (GTK/Pango/Cairo). Installez-les en suivant la documentation "
            "officielle de WeasyPrint, puis relancez la commande. "
            f"Détail technique : {erreur}"
        ) from erreur

    HTML(string=html).write_pdf(chemin_sortie)
