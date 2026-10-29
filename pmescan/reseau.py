"""Garde réseau : pmescan ne parle qu'à des adresses publiques.

Sans cette garde, un domaine qui pointe vers 127.0.0.1, 192.168.x.x ou 169.254.169.254
(ou un site qui redirige vers une telle adresse) ferait sonder par pmescan des services
internes : ceux de la machine de l'utilisateur ou de son réseau local.

Trois niveaux de protection :

1. ``adresses_publiques`` : avant le scan, la CLI résout le domaine et refuse toute cible
   dont une seule adresse n'est pas publique. L'adresse retenue est figée dans
   ``Cible.ip`` : le scan TLS (sslyze) et le scan de ports se connectent à cette adresse
   vérifiée, sans nouvelle résolution DNS.
2. ``TransportGarde``, avant l'envoi : chaque requête HTTP, redirections comprises, est
   revérifiée (schéma http/https, adresses résolues). Les vérifications intrusives
   n'acceptent en plus que les hôtes du site analysé.
3. ``TransportGarde``, après la connexion : l'adresse réellement jointe est contrôlée.
   Si le DNS a changé entre la vérification et la connexion (« DNS rebinding »), la
   réponse est rejetée avant d'être lue.
"""

import asyncio
import ipaddress
import socket
from typing import Any

import httpx

# Délai maximal d'une résolution DNS, en secondes.
_DELAI_RESOLUTION = 5.0


class CibleNonPublique(Exception):
    """Le nom résout vers au moins une adresse non publique (privée, locale, réservée…)."""

    def __init__(self, hote: str, adresses: list[str]) -> None:
        super().__init__(f"{hote} : {', '.join(adresses)}")
        self.hote = hote
        self.adresses = adresses


class RequeteBloquee(httpx.ConnectError):
    """Requête HTTP refusée par la garde réseau, avant l'envoi ou juste après la connexion.

    Hérite d'httpx.ConnectError : les vérifications la traitent comme une erreur réseau
    ordinaire (site injoignable, chemin non exposé).
    """


def adresse_publique(adresse: str) -> bool:
    """Vrai si ``adresse`` est une adresse IP publique, joignable sur Internet.

    Refuse les adresses privées (10/8, 172.16/12, 192.168/16, fc00::/7), locales
    (127/8, ::1), lien-local (169.254/16, dont les métadonnées des clouds, fe80::/10),
    réservées, de documentation et multicast, ainsi que les IPv4 encapsulées en IPv6
    (::ffff:127.0.0.1) qui pointent vers elles. Une chaîne qui n'est pas une adresse IP
    renvoie False.
    """
    try:
        # Retire l'éventuel identifiant de zone IPv6 (fe80::1%eth0).
        ip = ipaddress.ip_address(adresse.split("%", 1)[0])
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast


async def resoudre(hote: str) -> list[str]:
    """Résout ``hote`` en adresses IP (IPv4 et IPv6), sans doublon, dans l'ordre du DNS.

    Lève OSError si le nom est introuvable, mal formé ou trop lent à résoudre.
    """
    boucle = asyncio.get_running_loop()
    try:
        infos = await asyncio.wait_for(
            boucle.getaddrinfo(hote, None, type=socket.SOCK_STREAM), _DELAI_RESOLUTION
        )
    except TimeoutError as erreur:
        raise OSError(f"résolution DNS trop lente pour {hote}") from erreur
    except ValueError as erreur:
        # Nom mal formé (IDNA) : UnicodeError, sous-classe de ValueError.
        raise OSError(f"nom d'hôte invalide : {hote!r}") from erreur
    adresses: list[str] = []
    for _, _, _, _, adresse_socket in infos:
        adresse = str(adresse_socket[0])
        if adresse not in adresses:
            adresses.append(adresse)
    return adresses


async def adresses_publiques(hote: str) -> list[str]:
    """Résout ``hote`` et vérifie que TOUTES ses adresses sont publiques.

    Une adresse IP littérale est vérifiée sans résolution. Lève CibleNonPublique si une
    seule adresse ne l'est pas (un domaine peut mêler une adresse publique et une adresse
    interne), OSError si le nom est introuvable.
    """
    try:
        ipaddress.ip_address(hote)
        adresses = [hote]
    except ValueError:
        adresses = await resoudre(hote)
    interdites = [adresse for adresse in adresses if not adresse_publique(adresse)]
    if interdites:
        raise CibleNonPublique(hote, interdites)
    return adresses


def choisir_adresse(adresses: list[str]) -> str | None:
    """Renvoie la première adresse IPv4 de la liste, sinon la première ; None si vide."""
    for adresse in adresses:
        if ":" not in adresse:
            return adresse
    return adresses[0] if adresses else None


def hote_du_site(hote: str, domaine: str) -> bool:
    """Vrai si ``hote`` appartient au site analysé ``domaine``.

    Acceptés : le domaine lui-même, ses sous-domaines (www.exemple.sn pour exemple.sn) et,
    si le domaine commence par « www. », le domaine nu (exemple.sn pour www.exemple.sn).
    Tout autre hôte est un site tiers.
    """
    hote = hote.lower().rstrip(".")
    domaine = domaine.lower().rstrip(".")
    if hote == domaine or hote.endswith("." + domaine):
        return True
    return domaine.startswith("www.") and hote == domaine.removeprefix("www.")


def _adresse_jointe(reponse: httpx.Response) -> str | None:
    """Adresse IP réellement jointe pour cette réponse, ou None si elle est inconnue."""
    flux = reponse.extensions.get("network_stream")
    if flux is None:
        return None
    adresse = flux.get_extra_info("server_addr")
    if not adresse:
        return None
    return str(adresse[0])


class TransportGarde(httpx.AsyncBaseTransport):
    """Transport httpx qui applique la garde réseau à chaque requête, redirections comprises.

    ``meme_site=True`` limite en plus les requêtes aux hôtes du site analysé : à utiliser
    pour toute vérification qui demande des chemins sensibles, afin qu'une redirection ne
    l'entraîne jamais à sonder un site tiers.
    """

    def __init__(self, domaine: str, *, meme_site: bool, verify: bool = True) -> None:
        self._domaine = domaine
        self._meme_site = meme_site
        self._interne = httpx.AsyncHTTPTransport(verify=verify)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        await self._verifier_avant_envoi(request)
        reponse = await self._interne.handle_async_request(request)
        adresse = _adresse_jointe(reponse)
        if adresse is not None and not adresse_publique(adresse):
            await reponse.aclose()
            raise RequeteBloquee(
                f"connexion à une adresse non publique refusée ({adresse})", request=request
            )
        return reponse

    async def _verifier_avant_envoi(self, request: httpx.Request) -> None:
        """Lève RequeteBloquee si la requête vise un schéma, un hôte ou une adresse interdits."""
        url = request.url
        if url.scheme not in ("http", "https"):
            raise RequeteBloquee(f"schéma refusé : {url.scheme!r}", request=request)
        if self._meme_site and not hote_du_site(url.host, self._domaine):
            raise RequeteBloquee(
                f"hôte hors du site analysé refusé : {url.host!r}", request=request
            )
        try:
            await adresses_publiques(url.host)
        except CibleNonPublique as erreur:
            raise RequeteBloquee(
                f"adresse non publique refusée ({erreur})", request=request
            ) from erreur
        except OSError:
            # Nom introuvable : le transport httpx échouera de lui-même avec une erreur
            # réseau ordinaire. Le contrôle après connexion reste actif.
            pass

    async def aclose(self) -> None:
        await self._interne.aclose()


def client_garde(domaine: str, *, meme_site: bool, **options: Any) -> httpx.AsyncClient:
    """Crée un client httpx dont toutes les requêtes passent par la garde réseau.

    ``trust_env=False`` : un proxy défini dans l'environnement contournerait le transport
    gardé. Les autres options (timeout, follow_redirects…) sont transmises au client ;
    ``verify`` est transmis au transport.
    """
    verify = bool(options.pop("verify", True))
    transport = TransportGarde(domaine, meme_site=meme_site, verify=verify)
    return httpx.AsyncClient(transport=transport, trust_env=False, **options)
