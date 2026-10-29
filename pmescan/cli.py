"""Point d'entrée en ligne de commande de pmescan."""

import asyncio
import dataclasses
import io
import json
import sys
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _version_installee
from typing import Annotated

import typer

from pmescan.autorisation import ModeScan, exige_autorisation, journaliser_consentement
from pmescan.domaine import DomaineInvalide, valider_domaine
from pmescan.i18n import charger_textes
from pmescan.modele import Cible, Gravite, Resultat
from pmescan.notation import calculer_note
from pmescan.rapport.generateur import construire_contexte, ecrire_pdf, rendre_html
from pmescan.scanner import scanner

# Codes de sortie de la commande scan (voir README.md).
CODE_OK = 0
CODE_CRITIQUE = 1
CODE_ERREUR = 2
CODE_REFUS = 3

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


def _forcer_utf8() -> None:
    """Force l'encodage UTF-8 sur stdout et stderr.

    Sous Windows, une sortie redirigée (``pmescan scan ... --json > resultat.json``) prend
    sinon l'encodage local (cp1252) : les accents deviennent illisibles et le JSON produit
    n'est plus de l'UTF-8 valide. Les flux qui ne sont pas des TextIOWrapper sont ignorés.
    """
    for flux in (sys.stdout, sys.stderr):
        if isinstance(flux, io.TextIOWrapper):
            flux.reconfigure(encoding="utf-8")


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
    _forcer_utf8()


def _resultat_en_dict(resultat: Resultat) -> dict[str, object]:
    """Convertit un Resultat en dictionnaire sérialisable en JSON."""
    donnees = dataclasses.asdict(resultat)
    donnees["gravite"] = resultat.gravite.value
    return donnees


def _message_cli(cle: str, **valeurs: str) -> str:
    """Renvoie un message de la CLI tiré de la section ``cli`` de fr.yaml, complété."""
    messages = charger_textes("fr").get("cli", {})
    gabarit = str(messages[cle])
    return gabarit.format(**valeurs)


def _code_sortie(resultats: list[Resultat]) -> int:
    """1 si au moins un résultat CRITIQUE n'est pas réussi, sinon 0."""
    critique = any(
        resultat.gravite is Gravite.CRITIQUE and not resultat.reussi
        for resultat in resultats
    )
    return CODE_CRITIQUE if critique else CODE_OK


@app.command()
def scan(
    domaine: str = typer.Argument(..., help="Domaine à analyser, ex. exemple.com."),
    # Annotated : typer valide la valeur (code 2 si invalide) sans appel en défaut (B008).
    mode: Annotated[
        ModeScan,
        typer.Option(
            "--mode",
            help=(
                "Mode de scan : passif (défaut), actif ou agressif. Les modes actif et "
                "agressif exigent --jai-l-autorisation. agressif : réservé aux "
                "vérifications intrusives à venir ; équivaut aujourd'hui au mode actif."
            ),
        ),
    ] = ModeScan.PASSIF,
    autorisation: bool = typer.Option(
        False,
        "--jai-l-autorisation",
        help=(
            "Confirme que vous êtes propriétaire de la cible ou que vous disposez "
            "d'une autorisation écrite de son propriétaire. Obligatoire pour les "
            "modes actif et agressif."
        ),
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
    version, vérifications WordPress) et le test des ports. Le mode agressif équivaut
    aujourd'hui au mode actif.

    Garde d'autorisation : les modes actif et agressif exigent --jai-l-autorisation.
    Sans ce flag, aucune requête n'est envoyée et la commande quitte avec le code 3.
    Chaque scan intrusif autorisé est tracé dans ~/.pmescan/consent.log.

    Le domaine est validé et normalisé (minuscules, IDN en forme ASCII) avant tout :
    une URL, une adresse e-mail, un port ou un chemin sont refusés avec le code 2.

    Codes de sortie : 0 aucun problème critique, 1 au moins un problème critique,
    2 erreur (domaine invalide, PDF impossible, interruption, erreur imprévue),
    3 refus (mode intrusif sans autorisation).
    """
    # Filet de sécurité : toute exception imprévue devient un message clair et le code 2,
    # sans trace Python. typer.Exit (codes 0, 1, 2, 3 voulus) garde son comportement.
    # Depuis typer 0.2x, click est intégré à typer : typer.Exit et typer.Abort SONT les
    # exceptions Exit/Abort de click.
    try:
        code = _executer_scan(
            domaine, mode, autorisation, format_json, pdf, sortie, verifier_cve
        )
    except typer.Exit:
        raise
    except (KeyboardInterrupt, typer.Abort) as interruption:
        # Ctrl+C : on sort en code 2 (erreur) et non en 1, réservé aux problèmes critiques.
        typer.echo(_message_cli("interruption"), err=True)
        raise typer.Exit(code=CODE_ERREUR) from interruption
    except Exception as erreur:
        typer.echo(
            _message_cli("erreur_inattendue", erreur=f"{type(erreur).__name__} : {erreur}"),
            err=True,
        )
        raise typer.Exit(code=CODE_ERREUR) from erreur
    raise typer.Exit(code=code)


def _executer_scan(
    domaine: str,
    mode: ModeScan,
    autorisation: bool,
    format_json: bool,
    pdf: bool,
    sortie: str | None,
    verifier_cve: bool,
) -> int:
    """Corps de la commande scan ; renvoie le code de sortie (ou lève typer.Exit)."""
    # 1) Validation du domaine AVANT la garde et AVANT le journal : une valeur invalide
    # (URL, e-mail, port, chemin, caractère de contrôle) ne produit ni requête ni journal.
    try:
        domaine = valider_domaine(domaine)
    except DomaineInvalide:
        # repr() neutralise les caractères de contrôle de la saisie dans le terminal.
        typer.echo(_message_cli("domaine_invalide", domaine=repr(domaine)), err=True)
        raise typer.Exit(code=CODE_ERREUR) from None

    # 2) Garde d'autorisation des modes intrusifs, sur le domaine normalisé.
    intrusif_autorise = False
    if exige_autorisation(mode):
        if not autorisation:
            # Refus AVANT toute construction de cible ou requête réseau.
            typer.echo(
                _message_cli("refus_autorisation", mode=mode.value, domaine=domaine),
                err=True,
            )
            raise typer.Exit(code=CODE_REFUS)
        intrusif_autorise = True
        try:
            journaliser_consentement(domaine, mode)
        except OSError as erreur:
            typer.echo(_message_cli("avertissement_journal", erreur=str(erreur)), err=True)

    # autorisation=True seulement si le flag est passé EN mode intrusif : le scanner et le
    # check cms n'exécutent aucune requête intrusive sans cette confirmation explicite.
    cible = Cible(
        domaine=domaine,
        mode=mode.value,
        verifier_cve=verifier_cve,
        autorisation=intrusif_autorise,
    )
    resultats = asyncio.run(scanner(cible))
    code = _code_sortie(resultats)
    score, note = calculer_note(resultats)
    if pdf:
        chemin = sortie if sortie is not None else f"rapport-{domaine}.pdf"
        contexte = construire_contexte(cible, resultats, note, score)
        html = rendre_html(contexte)
        try:
            ecrire_pdf(html, chemin)
        except (RuntimeError, OSError) as erreur:
            typer.echo(
                _message_cli("erreur_pdf", chemin=chemin, erreur=str(erreur)), err=True
            )
            raise typer.Exit(code=CODE_ERREUR) from erreur
        typer.echo(f"Rapport PDF écrit : {chemin}")
        return code
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
    return code
