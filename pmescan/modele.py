"""Modèle de données commun à toutes les vérifications de pmescan."""

from dataclasses import dataclass, field
from enum import Enum


class Gravite(str, Enum):  # noqa: UP042 - signature publique à conserver
    """Niveau de gravité d'un problème détecté."""

    CRITIQUE = "critique"
    ELEVEE = "elevee"
    MOYENNE = "moyenne"
    FAIBLE = "faible"
    INFO = "info"


@dataclass
class Resultat:
    """Un problème (ou une absence de problème) trouvé par une vérification."""

    identifiant: str          # ex. "tls_expire", "dmarc_absent"
    gravite: Gravite
    reussi: bool              # True = aucun problème sur ce point
    preuve: str = ""          # donnée technique brute (ex. date d'expiration)
    details: dict[str, object] = field(default_factory=dict)


@dataclass
class Cible:
    """Site à analyser et mode de scan demandé."""

    domaine: str
    ip: str | None = None
    mode: str = "passif"      # "passif" | "actif" | "agressif"
    # OPT-IN : la vérification des CVE via l'API publique osv.dev envoie le nom et la
    # version du CMS détecté à un tiers. Désactivée par défaut pour respecter le principe
    # « aucune donnée envoyée à un tiers » (voir README.md, « Vie privée »).
    verifier_cve: bool = False
    # DÉFENSE EN PROFONDEUR : vrai seulement si l'utilisateur a explicitement confirmé
    # disposer d'une autorisation sur la cible (--jai-l-autorisation en mode intrusif).
    # Sans elle, même si ``mode`` vaut « actif » ou « agressif » : scanner() ignore les
    # vérifications intrusives, ces checks (ports, exposes) renvoient une liste vide
    # s'ils sont appelés directement, et le check cms ne sonde aucun chemin. L'API
    # Python ne lance jamais de requête intrusive sans autorisation explicite.
    autorisation: bool = False
