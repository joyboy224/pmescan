"""Fixtures partagées et fabriques d'objets factices pour les tests hors-ligne.

Aucun test ne doit toucher au réseau. On rejoue des réponses enregistrées
(`tests/fixtures/`) via respx pour httpx, et on remplace les objets de scan
sslyze par de simples objets factices construits ici.
"""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from sslyze import ScanCommandAttemptStatusEnum, ServerScanStatusEnum

DOSSIER_FIXTURES = Path(__file__).parent / "fixtures"


def charger_fixture(nom: str) -> dict:
    """Charge une réponse enregistrée depuis tests/fixtures/."""
    chemin = DOSSIER_FIXTURES / nom
    return json.loads(chemin.read_text(encoding="utf-8"))


# --- Fabriques d'objets factices sslyze --------------------------------------


class FauxChiffrement:
    """Imite un `cipher_suite` sslyze (nom, taille de clé, anonymat)."""

    def __init__(self, name: str, key_size: int = 256, is_anonymous: bool = False) -> None:
        self.name = name
        self.key_size = key_size
        self.is_anonymous = is_anonymous


class FauxChiffrementAccepte:
    """Imite une entrée `accepted_cipher_suites` de sslyze."""

    def __init__(self, suite: FauxChiffrement) -> None:
        self.cipher_suite = suite


class FauxResultatChiffrements:
    """Remplace `CipherSuitesScanResult` : porte `accepted_cipher_suites`.

    On remplace la référence `pmescan.checks.tls.CipherSuitesScanResult` par
    cette classe dans les tests concernés pour que les ``isinstance`` passent.
    """

    def __init__(self, acceptes: list[FauxChiffrementAccepte]) -> None:
        self.accepted_cipher_suites = acceptes


def tentative_chiffrements(acceptes: list[FauxChiffrementAccepte]) -> SimpleNamespace:
    """Tentative de scan « réussie » portant une liste de chiffrements acceptés."""
    return SimpleNamespace(
        status=ScanCommandAttemptStatusEnum.COMPLETED,
        result=FauxResultatChiffrements(acceptes),
    )


def tentative_absente() -> SimpleNamespace:
    """Tentative non exécutée (protocole non accepté / non testé)."""
    return SimpleNamespace(status=ScanCommandAttemptStatusEnum.NOT_SCHEDULED, result=None)


def construire_certificat(jours_avant_expiration: int) -> SimpleNamespace:
    """Construit la tentative `certificate_info` avec une feuille qui expire dans N jours."""
    expiration = datetime.now(UTC) + timedelta(days=jours_avant_expiration)
    feuille = SimpleNamespace(not_valid_after_utc=expiration)
    deploiement = SimpleNamespace(received_certificate_chain=[feuille])
    resultat = SimpleNamespace(certificate_deployments=[deploiement])
    return SimpleNamespace(status=ScanCommandAttemptStatusEnum.COMPLETED, result=resultat)


def construire_scan_result(
    *,
    jours_avant_expiration: int = 365,
    tls_1_0: SimpleNamespace | None = None,
    tls_1_1: SimpleNamespace | None = None,
    tls_1_2: SimpleNamespace | None = None,
) -> SimpleNamespace:
    """Assemble un `scan_result` factice complet avec des valeurs saines par défaut."""
    return SimpleNamespace(
        certificate_info=construire_certificat(jours_avant_expiration),
        ssl_2_0_cipher_suites=tentative_absente(),
        ssl_3_0_cipher_suites=tentative_absente(),
        tls_1_0_cipher_suites=tls_1_0 or tentative_absente(),
        tls_1_1_cipher_suites=tls_1_1 or tentative_absente(),
        tls_1_2_cipher_suites=tls_1_2 or tentative_chiffrements(
            [FauxChiffrementAccepte(FauxChiffrement("TLS_AES_256_GCM_SHA384"))]
        ),
        tls_1_3_cipher_suites=tentative_absente(),
    )


def construire_rapport(scan_result: SimpleNamespace | None) -> SimpleNamespace:
    """Enveloppe un `scan_result` dans un rapport serveur factice (scan terminé)."""
    statut = (
        ServerScanStatusEnum.COMPLETED
        if scan_result is not None
        else ServerScanStatusEnum.ERROR_NO_CONNECTIVITY
    )
    return SimpleNamespace(
        scan_status=statut,
        scan_result=scan_result,
        connectivity_error_trace=None,
    )


@pytest.fixture
def cible_exemple():
    """Cible passive standard pointant sur exemple.com."""
    from pmescan.modele import Cible

    return Cible(domaine="exemple.com", mode="passif")


# --- Fabrique de fausse connexion TCP (scan de ports) ------------------------

# Adresse IP factice (plage de documentation TEST-NET-1, RFC 5737) renvoyée par la fausse
# résolution : aucun test de ports ne doit dépendre du vrai DNS.
ADRESSE_FACTICE = "192.0.2.10"


class FauxEcrivain:
    """Imite le StreamWriter d'asyncio : compte les appels à ``close()``."""

    def __init__(self) -> None:
        self.fermetures = 0

        async def _attendre_fermeture() -> None:
            return None

        # Le code de production attend l'API asyncio : méthode ``wait_closed``.
        self.wait_closed = _attendre_fermeture

    def close(self) -> None:
        self.fermetures += 1


def faux_open_connection(ports_ouverts: set[int], ecrivains: list | None = None):
    """Fausse ``asyncio.open_connection`` : réussit pour ``ports_ouverts``, échoue sinon.

    Aucune socket réelle n'est ouverte. Les ports hors de l'ensemble lèvent ``OSError``
    (interprété par le check comme « port fermé ou filtré »). Si ``ecrivains`` est fourni,
    chaque faux écrivain créé y est ajouté pour vérifier ensuite sa fermeture.
    """

    async def _ouvrir(hote, port):
        if port in ports_ouverts:
            ecrivain = FauxEcrivain()
            if ecrivains is not None:
                ecrivains.append(ecrivain)
            return SimpleNamespace(), ecrivain
        raise OSError("connexion refusée")

    return _ouvrir


def faux_resoudre(adresse: str | None = ADRESSE_FACTICE):
    """Fausse ``VerificationPorts._resoudre`` : renvoie ``adresse`` sans aucun DNS.

    ``adresse=None`` simule un nom d'hôte introuvable.
    """

    async def _resoudre(self, hote):
        return adresse

    return _resoudre


# --- Garde réseau : résolution DNS factice -----------------------------------

# Adresse publique factice renvoyée par la fausse résolution de pmescan.reseau. Elle doit
# être publique (contrairement à ADRESSE_FACTICE, en TEST-NET) pour passer la garde.
ADRESSE_PUBLIQUE_FACTICE = "93.184.215.14"


@pytest.fixture(autouse=True)
def resolution_factice(monkeypatch):
    """Remplace la résolution DNS de la garde réseau pour TOUS les tests : aucun vrai DNS.

    Chaque nom résout vers les adresses de la liste renvoyée (par défaut
    ADRESSE_PUBLIQUE_FACTICE). Un test la modifie pour simuler un autre DNS, par exemple
    ``resolution_factice[:] = ["127.0.0.1"]``. Une liste vide simule un nom introuvable.
    """
    import pmescan.reseau as reseau

    adresses = [ADRESSE_PUBLIQUE_FACTICE]

    async def _resoudre(hote):
        if not adresses:
            raise OSError(f"nom introuvable : {hote}")
        return list(adresses)

    monkeypatch.setattr(reseau, "resoudre", _resoudre)
    return adresses
