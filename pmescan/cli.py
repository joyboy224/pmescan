"""Point d'entrée en ligne de commande de pmescan."""

import asyncio
import dataclasses
import json
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _version_installee

import typer

from pmescan.modele import Cible, Resultat
from pmescan.notation import calculer_note
from pmescan.rapport.generateur import construire_contexte, ecrire_pdf, rendre_html
from pmescan.scanner import scanner

app = typer.Typer(
    name="pmescan",
    help="Scanner de sécurité pour PME francophones.",
    add_completion=False,
)


def obtenir_version() -> str:
    """Renvoie la version du paquet (installée, ou celle du code source)."""
    try:
        return _version_installee("pmescan")
    except PackageNotFoundError:
        from pmescan import __version__

        return __version__


def _rappel_version(demandee: bool) -> None:
    """Affiche la version puis quitte, lorsque l'option --version est passée."""
    if demandee:
        typer.echo(f"pmescan {obtenir_version()}")
        raise typer.Exit()


@app.callback()
def principal(
    version: bool = typer.Option(
        False,
        "--version",
        callback=_rappel_version,
        is_eager=True,
        help="Affiche la version et quitte.",
    ),
) -> None:
    """pmescan — scanner de sécurité pour PME francophones."""


def _resultat_en_dict(resultat: Resultat) -> dict[str, object]:
    """Convertit un Resultat en dictionnaire sérialisable en JSON."""
    donnees = dataclasses.asdict(resultat)
    donnees["gravite"] = resultat.gravite.value
    return donnees


@app.command()
def scan(
    domaine: str = typer.Argument(..., help="Domaine à analyser, ex. exemple.com."),
    mode: str = typer.Option(
        "passif", "--mode", help="Mode de scan : passif, actif ou agressif."
    ),
    format_json: bool = typer.Option(
        False, "--json", help="Affiche les résultats agrégés au format JSON."
    ),
    pdf: bool = typer.Option(
        False, "--pdf", help="Génère un rapport PDF en français clair."
    ),
    sortie: str | None = typer.Option(
        None,
        "--sortie",
        help="Chemin du fichier PDF à écrire (défaut : rapport-<domaine>.pdf).",
    ),
    verifier_cve: bool = typer.Option(
        False,
        "--verifier-cve",
        help=(
            "Vérifie les CVE connues du CMS via l'API publique osv.dev. "
            "Désactivé par défaut : cette option contacte un tiers (osv.dev). Seuls le "
            "nom et la version du CMS détecté lui sont envoyés, jamais le domaine analysé."
        ),
    ),
) -> None:
    """Analyse un domaine et affiche les résultats.

    Le scan couvre TLS, en-têtes, DNS/messagerie et la détection du CMS (page d'accueil).
    En mode actif, il ajoute les fichiers exposés, la sonde de chemins CMS (fichiers de
    version, vérifications WordPress) et le test des ports.
    """
    cible = Cible(domaine=domaine, mode=mode, verifier_cve=verifier_cve)
    resultats = asyncio.run(scanner(cible))
    score, note = calculer_note(resultats)
    if pdf:
        chemin = sortie if sortie is not None else f"rapport-{domaine}.pdf"
        contexte = construire_contexte(cible, resultats, note, score)
        html = rendre_html(contexte)
        try:
            ecrire_pdf(html, chemin)
        except RuntimeError as erreur:
            typer.echo(str(erreur), err=True)
            raise typer.Exit(code=1) from erreur
        typer.echo(f"Rapport PDF écrit : {chemin}")
        return
    if format_json:
        charge: dict[str, object] = {
            "note": note,
            "score": score,
            "resultats": [_resultat_en_dict(resultat) for resultat in resultats],
        }
        typer.echo(json.dumps(charge, ensure_ascii=False, indent=2))
    else:
        for resultat in resultats:
            etat = "OK" if resultat.reussi else "PROBLEME"
            typer.echo(f"[{etat}] {resultat.identifiant} ({resultat.gravite.value})")
        typer.echo(f"Note globale : {note} ({score}/100)")
