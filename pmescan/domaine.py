"""Validation et normalisation du domaine passé à pmescan.

Le domaine est validé AVANT la garde d'autorisation et avant le journal de consentement :
une valeur invalide (URL complète, adresse e-mail, port, chemin, caractère de contrôle…)
est refusée sans qu'aucune requête ne parte et sans qu'aucune ligne ne soit journalisée.
"""

import ipaddress
import re

import idna

# Longueur maximale d'un nom d'hôte complet, sans le point final (RFC 1035).
_LONGUEUR_MAX = 253

# Un label ASCII : 1 à 63 caractères, lettres, chiffres et tirets, sans tiret en début ni
# en fin de label. La vérification se fait APRÈS l'encodage IDNA (forme « xn-- »).
_MOTIF_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")

# Caractères qui trahissent une URL, une adresse e-mail, un port ou un chemin.
_CARACTERES_INTERDITS = frozenset("/:@\\?#[]%")


class DomaineInvalide(ValueError):
    """Le domaine fourni n'est pas un nom d'hôte valide."""


def valider_domaine(domaine: str) -> str:
    """Valide ``domaine`` et renvoie sa forme normalisée (ASCII, minuscules).

    Acceptés : noms d'hôte dont chaque label fait 1 à 63 caractères (lettres, chiffres,
    tirets, sans tiret en début ni en fin), longueur totale ≤ 253 ; un point final est
    toléré puis retiré ; les noms internationalisés (IDN) sont convertis en forme
    ASCII via le paquet ``idna`` (IDNA 2008, UTS 46 non transitionnel), par ex.
    « café.fr » -> « xn--caf-dma.fr » et « faß.de » -> « xn--fa-hia.de ».

    Formes numériques : si le DERNIER label est entièrement numérique, le nom n'est
    accepté que s'il s'agit d'une adresse IPv4 canonique (``1.2.3.4``). Les formes
    ambiguës (``2130706433``, ``127.1``, ``0x7f.1``, ``01.2.3.4``…) sont refusées.

    Refusés : schéma (``https://``), ``@``, ``/``, ``:`` (donc port), espace, chemin et
    tout caractère non imprimable. Lève :class:`DomaineInvalide` dans ces cas.
    """
    if not domaine or any(
        caractere in _CARACTERES_INTERDITS
        or caractere.isspace()
        or not caractere.isprintable()
        for caractere in domaine
    ):
        raise DomaineInvalide(domaine)

    # Point final toléré (nom absolu), retiré une seule fois.
    sans_point_final = domaine[:-1] if domaine.endswith(".") else domaine
    if not sans_point_final:
        raise DomaineInvalide(domaine)

    try:
        # Paquet idna (IDNA 2008 + UTS 46, non transitionnel) et NON le codec « idna »
        # de Python : ce dernier suit IDNA 2003 et substitue des caractères (« faß.de »
        # deviendrait « fass.de », un AUTRE domaine). uts46=True normalise aussi la casse.
        nom_ascii = (
            idna.encode(sans_point_final, uts46=True, transitional=False)
            .decode("ascii")
            .lower()
        )
    except (idna.IDNAError, UnicodeError) as erreur:
        raise DomaineInvalide(domaine) from erreur

    if len(nom_ascii) > _LONGUEUR_MAX:
        raise DomaineInvalide(domaine)
    labels = nom_ascii.split(".")
    if not all(_MOTIF_LABEL.fullmatch(label) for label in labels):
        raise DomaineInvalide(domaine)

    # Dernier label tout numérique : seule une IPv4 canonique est acceptée, pour éviter
    # les formes que certains résolveurs interprètent comme une adresse (127.1, 2130706433).
    if labels[-1].isdigit():
        try:
            canonique = str(ipaddress.IPv4Address(nom_ascii)) == nom_ascii
        except ValueError:
            canonique = False
        if not canonique:
            raise DomaineInvalide(domaine)
    return nom_ascii
