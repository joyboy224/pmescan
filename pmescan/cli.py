"""Point d'entrée en ligne de commande de pmescan."""

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _version_installee

import typer

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
    """pmescan — scanner de sécurité pour PME francophones.

    Les commandes de scan seront ajoutées aux étapes suivantes.
    """
