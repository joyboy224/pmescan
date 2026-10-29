"""Scan de ports TCP sensibles sans dépendance externe (mode actif).

Ce check est intrusif : il ouvre des connexions TCP vers la cible. Il ne s'active donc
qu'à partir du mode « actif ». Aucune dépendance type nmap n'est utilisée : on s'appuie
uniquement sur ``asyncio.open_connection`` avec un délai court, et la concurrence est
bornée par un sémaphore.
"""

import asyncio

from pmescan.checks.base import Verification
from pmescan.modele import Cible, Gravite, Resultat
from pmescan.reseau import CibleNonPublique, adresses_publiques, choisir_adresse

# Délai maximal d'une tentative de connexion TCP (secondes).
_DELAI_CONNEXION = 2.0

# Nombre maximal de connexions simultanées, pour ne pas saturer la cible ni la machine.
_CONCURRENCE_MAX = 20

# Ports surveillés : (port, clé de service, gravité si ouvert).
# Bases de données, caches, partage de fichiers Windows (SMB) et accès distant complet
# (RDP, VNC, API Docker) -> CRITIQUE.
# Autres services d'administration ou de fichiers -> ELEVEE.
# Messagerie et interfaces web secondaires -> MOYENNE.
# Ports web attendus (80, 443) -> INFO, réussi (voir _PORTS_ATTENDUS).
_PORTS: tuple[tuple[int, str, Gravite], ...] = (
    (21, "ftp", Gravite.ELEVEE),
    (22, "ssh", Gravite.ELEVEE),
    (23, "telnet", Gravite.ELEVEE),
    (25, "smtp", Gravite.MOYENNE),
    (110, "pop3", Gravite.MOYENNE),
    (135, "rpc", Gravite.ELEVEE),
    (139, "netbios", Gravite.ELEVEE),
    (143, "imap", Gravite.MOYENNE),
    (161, "snmp", Gravite.ELEVEE),
    (389, "ldap", Gravite.ELEVEE),
    (445, "smb", Gravite.CRITIQUE),
    (1433, "mssql", Gravite.CRITIQUE),
    (1521, "oracle", Gravite.CRITIQUE),
    (2375, "docker", Gravite.CRITIQUE),
    (3000, "web_3000", Gravite.MOYENNE),
    (3306, "mysql", Gravite.CRITIQUE),
    (3389, "rdp", Gravite.CRITIQUE),
    (5432, "postgresql", Gravite.CRITIQUE),
    (5601, "kibana", Gravite.ELEVEE),
    (5900, "vnc", Gravite.CRITIQUE),
    (5984, "couchdb", Gravite.CRITIQUE),
    (5985, "winrm", Gravite.ELEVEE),
    (6379, "redis", Gravite.CRITIQUE),
    (8080, "http_alt", Gravite.MOYENNE),
    (9200, "elasticsearch", Gravite.CRITIQUE),
    (11211, "memcached", Gravite.CRITIQUE),
    (15672, "rabbitmq", Gravite.ELEVEE),
    (27017, "mongodb", Gravite.CRITIQUE),
    (80, "http", Gravite.INFO),
    (443, "https", Gravite.INFO),
)

# Ports web dont l'ouverture est attendue pour un site : signalés en INFO « réussi ».
# La redirection HTTP -> HTTPS du port 80 est déjà contrôlée par le module tls.
_PORTS_ATTENDUS = {80, 443}


class VerificationPorts(Verification):
    """Teste l'ouverture d'un jeu de ports TCP sensibles par connexion directe."""

    nom = "ports"
    niveau_minimum = "actif"

    async def executer(self, cible: Cible) -> list[Resultat]:
        # Défense en profondeur : même appelé directement en Python, ce check intrusif
        # n'ouvre aucune connexion sans autorisation explicite.
        if not cible.autorisation:
            return []
        hote = cible.ip or cible.domaine

        # Résolution UNIQUE avant la boucle : toutes les connexions visent la même adresse,
        # et un nom introuvable donne un seul résultat au lieu de trente échecs.
        try:
            adresse = await self._resoudre(hote)
        except CibleNonPublique as erreur:
            # Garde réseau : aucun port d'une adresse privée ou locale n'est testé.
            return [
                Resultat(
                    identifiant="ports_cible_non_publique",
                    gravite=Gravite.INFO,
                    reussi=False,
                    preuve=str(erreur),
                    details={"hote": hote, "adresses": erreur.adresses},
                )
            ]
        if adresse is None:
            return [
                Resultat(
                    identifiant="ports_hote_introuvable",
                    gravite=Gravite.INFO,
                    reussi=False,
                    preuve=hote,
                    details={"hote": hote},
                )
            ]

        semaphore = asyncio.Semaphore(_CONCURRENCE_MAX)
        taches = [
            self._tester_port(adresse, port, semaphore) for port, _, _ in _PORTS
        ]
        etats = await asyncio.gather(*taches)

        resultats: list[Resultat] = []
        for (port, service, gravite), ouvert in zip(_PORTS, etats, strict=True):
            if not ouvert:
                continue
            attendu = port in _PORTS_ATTENDUS
            # Port web attendu (HTTP, HTTPS) : comportement normal d'un site web.
            resultats.append(
                Resultat(
                    identifiant=f"port_ouvert_{service}",
                    gravite=Gravite.INFO if attendu else gravite,
                    reussi=attendu,
                    preuve=f"{hote}:{port}",
                    details={"port": port, "service": service, "adresse": adresse},
                )
            )

        if all(resultat.reussi for resultat in resultats):
            resultats.append(
                Resultat(
                    identifiant="aucun_port_sensible",
                    gravite=Gravite.INFO,
                    reussi=True,
                    details={"hote": hote},
                )
            )
        return resultats

    async def _resoudre(self, hote: str) -> str | None:
        """Résout ``hote`` en une adresse IP publique, sinon None.

        On préfère la première adresse IPv4 ; à défaut, la première renvoyée. La
        résolution est bornée par _DELAI_CONNEXION. Un nom introuvable, invalide ou trop
        lent à résoudre renvoie None. Lève CibleNonPublique si une adresse n'est pas
        publique (garde réseau, voir pmescan.reseau).
        """
        try:
            adresses = await asyncio.wait_for(adresses_publiques(hote), _DELAI_CONNEXION)
        except (TimeoutError, OSError):
            return None
        return choisir_adresse(adresses)

    async def _tester_port(
        self, adresse: str, port: int, semaphore: asyncio.Semaphore
    ) -> bool:
        """Tente une connexion TCP ; renvoie True si le port accepte la connexion.

        Toute erreur (délai dépassé, connexion refusée, hôte injoignable, paramètre
        invalide) est interprétée comme « port fermé ou filtré » : aucune exception ne
        remonte.
        """
        async with semaphore:
            connexion = asyncio.open_connection(adresse, port)
            try:
                _, ecrivain = await asyncio.wait_for(connexion, timeout=_DELAI_CONNEXION)
            except (TimeoutError, OSError, ValueError):
                return False
            ecrivain.close()
            try:
                await asyncio.wait_for(ecrivain.wait_closed(), _DELAI_CONNEXION)
            except (TimeoutError, OSError):
                # La fermeture peut échouer ou traîner si le pair coupe brutalement :
                # sans incidence, le port a bien accepté la connexion.
                pass
            return True
