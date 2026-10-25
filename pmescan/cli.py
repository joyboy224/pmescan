"""Point d'entrée en ligne de commande de pmescan."""

import asyncio
import dataclasses
import json
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _version_installee

import typer

from pmescan.modele import Cible, Resultat
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
) -> None:
    """Analyse un domaine (TLS et en-têtes) et affiche les résultats."""
    cible = Cible(domaine=domaine, mode=mode)
    resultats = asyncio.run(scanner(cible))
    if format_json:
        charge = [_resultat_en_dict(resultat) for resultat in resultats]
        typer.echo(json.dumps(charge, ensure_ascii=False, indent=2))
    else:
        for resultat in resultats:
            etat = "OK" if resultat.reussi else "PROBLEME"
            typer.echo(f"[{etat}] {resultat.identifiant} ({resultat.gravite.value})")
