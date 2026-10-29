"""Vérification TLS : certificat, protocoles obsolètes, chiffrements faibles, redirection."""

import asyncio
from datetime import UTC, datetime

import httpx
from sslyze import (
    CipherSuitesScanResult,
    ScanCommand,
    ScanCommandAttemptStatusEnum,
    Scanner,
    ServerNetworkLocation,
    ServerScanRequest,
    ServerScanResult,
    ServerScanStatusEnum,
)

from pmescan.checks.base import Verification
from pmescan.modele import Cible, Gravite, Resultat
from pmescan.reseau import client_garde

# Nombre de jours en dessous duquel on considère le certificat « proche expiration ».
SEUIL_EXPIRATION_JOURS = 30

# Fragments de nom qui trahissent un chiffrement faible (insensible à la casse).
_FRAGMENTS_FAIBLES = ("NULL", "EXPORT", "RC4", "_DES_", "3DES", "MD5", "ANON")


class VerificationTls(Verification):
    """Analyse la configuration TLS d'une cible via sslyze et httpx."""

    nom = "tls"
    niveau_minimum = "passif"

    async def executer(self, cible: Cible) -> list[Resultat]:
        resultats: list[Resultat] = []
        # sslyze est synchrone : on l'exécute dans un fil pour ne pas bloquer la boucle.
        try:
            rapport = await asyncio.to_thread(self._scanner_sslyze, cible)
        except Exception as erreur:  # pragma: no cover - dépend du réseau
            return [
                Resultat(
                    identifiant="tls_erreur_connexion",
                    gravite=Gravite.INFO,
                    reussi=False,
                    preuve=str(erreur),
                    details={"domaine": cible.domaine},
                )
            ]

        if rapport.scan_status != ServerScanStatusEnum.COMPLETED or rapport.scan_result is None:
            return [
                Resultat(
                    identifiant="tls_injoignable",
                    gravite=Gravite.INFO,
                    reussi=False,
                    preuve=str(rapport.connectivity_error_trace or "hôte injoignable"),
                    details={"domaine": cible.domaine},
                )
            ]

        resultats.extend(self._analyser_certificat(rapport))
        resultats.extend(self._analyser_protocoles_et_chiffrements(rapport))
        resultats.append(await self._verifier_redirection(cible))
        return resultats

    def _scanner_sslyze(self, cible: Cible) -> ServerScanResult:
        """Lance le scan sslyze bloquant et renvoie le résultat du serveur."""
        emplacement = ServerNetworkLocation(hostname=cible.domaine, ip_address=cible.ip)
        requete = ServerScanRequest(
            server_location=emplacement,
            scan_commands={
                ScanCommand.CERTIFICATE_INFO,
                ScanCommand.SSL_2_0_CIPHER_SUITES,
                ScanCommand.SSL_3_0_CIPHER_SUITES,
                ScanCommand.TLS_1_0_CIPHER_SUITES,
                ScanCommand.TLS_1_1_CIPHER_SUITES,
                ScanCommand.TLS_1_2_CIPHER_SUITES,
                ScanCommand.TLS_1_3_CIPHER_SUITES,
            },
        )
        scanner = Scanner()
        scanner.queue_scans([requete])
        for resultat_serveur in scanner.get_results():
            return resultat_serveur
        raise RuntimeError("sslyze n'a renvoyé aucun résultat")

    def _analyser_certificat(self, rapport: ServerScanResult) -> list[Resultat]:
        """Détecte un certificat expiré ou proche de l'expiration."""
        resultats: list[Resultat] = []
        assert rapport.scan_result is not None
        tentative = rapport.scan_result.certificate_info
        if tentative.status != ScanCommandAttemptStatusEnum.COMPLETED or tentative.result is None:
            return resultats

        maintenant = datetime.now(UTC)
        for deploiement in tentative.result.certificate_deployments:
            if not deploiement.received_certificate_chain:
                continue
            feuille = deploiement.received_certificate_chain[0]
            expiration = feuille.not_valid_after_utc
            jours_restants = (expiration - maintenant).days
            if jours_restants < 0:
                resultats.append(
                    Resultat(
                        identifiant="tls_expire",
                        gravite=Gravite.CRITIQUE,
                        reussi=False,
                        preuve=expiration.isoformat(),
                        details={"jours_restants": jours_restants},
                    )
                )
            elif jours_restants <= SEUIL_EXPIRATION_JOURS:
                resultats.append(
                    Resultat(
                        identifiant="tls_expiration_proche",
                        gravite=Gravite.MOYENNE,
                        reussi=False,
                        preuve=expiration.isoformat(),
                        details={"jours_restants": jours_restants},
                    )
                )
            # Un seul déploiement suffit pour le constat d'expiration.
            break

        if not resultats:
            resultats.append(
                Resultat(identifiant="tls_certificat_valide", gravite=Gravite.INFO, reussi=True)
            )
        return resultats

    def _analyser_protocoles_et_chiffrements(
        self, rapport: ServerScanResult
    ) -> list[Resultat]:
        """Détecte SSL/TLS obsolètes activés et les chiffrements faibles."""
        resultats: list[Resultat] = []
        assert rapport.scan_result is not None
        resultat_scan = rapport.scan_result

        # Protocoles obsolètes : SSL 2.0/3.0 et TLS 1.0/1.1 encore acceptés.
        protocoles_obsoletes = {
            "SSLv2": resultat_scan.ssl_2_0_cipher_suites,
            "SSLv3": resultat_scan.ssl_3_0_cipher_suites,
            "TLSv1.0": resultat_scan.tls_1_0_cipher_suites,
            "TLSv1.1": resultat_scan.tls_1_1_cipher_suites,
        }
        protocoles_actifs: list[str] = []
        for nom_protocole, tentative in protocoles_obsoletes.items():
            if self._protocole_accepte(tentative):
                protocoles_actifs.append(nom_protocole)
        if protocoles_actifs:
            resultats.append(
                Resultat(
                    identifiant="tls_protocole_obsolete",
                    gravite=Gravite.ELEVEE,
                    reussi=False,
                    preuve=", ".join(protocoles_actifs),
                    details={"protocoles": protocoles_actifs},
                )
            )

        # Chiffrements faibles, toutes versions TLS confondues.
        chiffrements_faibles = self._collecter_chiffrements_faibles(resultat_scan)
        if chiffrements_faibles:
            resultats.append(
                Resultat(
                    identifiant="tls_chiffrement_faible",
                    gravite=Gravite.ELEVEE,
                    reussi=False,
                    preuve=", ".join(sorted(chiffrements_faibles)),
                    details={"chiffrements": sorted(chiffrements_faibles)},
                )
            )

        if not resultats:
            resultats.append(
                Resultat(identifiant="tls_protocoles_sains", gravite=Gravite.INFO, reussi=True)
            )
        return resultats

    def _protocole_accepte(
        self, tentative: object
    ) -> bool:
        """Vrai si la version de protocole a au moins un chiffrement accepté."""
        statut = getattr(tentative, "status", None)
        resultat = getattr(tentative, "result", None)
        if statut != ScanCommandAttemptStatusEnum.COMPLETED or resultat is None:
            return False
        assert isinstance(resultat, CipherSuitesScanResult)
        return len(resultat.accepted_cipher_suites) > 0

    def _collecter_chiffrements_faibles(self, resultat_scan: object) -> set[str]:
        """Rassemble les noms de chiffrements faibles acceptés par le serveur."""
        faibles: set[str] = set()
        attributs = (
            "tls_1_0_cipher_suites",
            "tls_1_1_cipher_suites",
            "tls_1_2_cipher_suites",
        )
        for attribut in attributs:
            tentative = getattr(resultat_scan, attribut, None)
            statut = getattr(tentative, "status", None)
            resultat = getattr(tentative, "result", None)
            if statut != ScanCommandAttemptStatusEnum.COMPLETED or resultat is None:
                continue
            assert isinstance(resultat, CipherSuitesScanResult)
            for accepte in resultat.accepted_cipher_suites:
                suite = accepte.cipher_suite
                nom_majuscule = suite.name.upper()
                est_faible = (
                    suite.is_anonymous
                    or suite.key_size < 128
                    or any(fragment in nom_majuscule for fragment in _FRAGMENTS_FAIBLES)
                )
                if est_faible:
                    faibles.add(suite.name)
        return faibles

    async def _verifier_redirection(self, cible: Cible) -> Resultat:
        """Vérifie qu'une requête HTTP est redirigée vers HTTPS."""
        url = f"http://{cible.domaine}/"
        try:
            # verify=False délibéré : la validité du certificat est traitée plus haut par
            # sslyze. Ce client httpx ne teste que la joignabilité et la redirection, et
            # ne doit pas échouer sur un certificat invalide.
            # Garde réseau : adresses publiques seulement, redirections comprises.
            async with client_garde(
                cible.domaine,
                meme_site=False,
                follow_redirects=True,
                timeout=10.0,
                verify=False,
            ) as client:
                reponse = await client.get(url)
        except httpx.HTTPError as erreur:
            return Resultat(
                identifiant="tls_redirection_indeterminee",
                gravite=Gravite.INFO,
                reussi=True,
                preuve=str(erreur),
                details={"url": url},
            )

        url_finale = str(reponse.url)
        if url_finale.startswith("https://"):
            return Resultat(
                identifiant="tls_redirection_https",
                gravite=Gravite.INFO,
                reussi=True,
                preuve=url_finale,
            )
        return Resultat(
            identifiant="tls_redirection_absente",
            gravite=Gravite.MOYENNE,
            reussi=False,
            preuve=url_finale,
            details={"url_initiale": url},
        )
