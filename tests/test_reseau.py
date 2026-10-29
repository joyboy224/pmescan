"""Tests de la garde réseau (pmescan.reseau) : adresses publiques, hôtes du site, transport.

Aucun accès à Internet. La résolution DNS est remplacée par la fixture automatique
``resolution_factice`` (voir conftest.py). Les tests de ``resoudre`` utilisent la vraie
fonction, importée avant ce remplacement, avec un ``getaddrinfo`` factice. Le test de
« DNS rebinding » ouvre un vrai petit serveur HTTP, mais seulement sur 127.0.0.1.
"""

import asyncio
import http.server
import socket
import threading

import httpx
import pytest

from pmescan.reseau import (
    CibleNonPublique,
    RequeteBloquee,
    TransportGarde,
    adresse_publique,
    adresses_publiques,
    choisir_adresse,
    client_garde,
    hote_du_site,
)
from pmescan.reseau import resoudre as resoudre_reel
from tests.conftest import ADRESSE_PUBLIQUE_FACTICE

DOMAINE = "exemple.com"


# --- adresse_publique ---------------------------------------------------------


@pytest.mark.parametrize(
    "adresse",
    ["93.184.215.14", "8.8.8.8", "2606:2800:21f:cb07::1"],
)
def test_adresses_publiques_acceptees(adresse):
    """Des adresses joignables sur Internet sont publiques."""
    assert adresse_publique(adresse) is True


@pytest.mark.parametrize(
    "adresse",
    [
        "127.0.0.1",          # boucle locale
        "10.0.0.5",           # privée
        "172.16.3.4",         # privée
        "192.168.1.10",       # privée
        "169.254.169.254",    # lien-local : métadonnées des clouds
        "100.64.0.1",         # CGNAT (espace partagé)
        "0.0.0.0",            # non spécifiée
        "192.0.2.10",         # documentation (TEST-NET-1)
        "224.0.0.1",          # multicast
        "::1",                # boucle locale IPv6
        "fe80::1%eth0",       # lien-local IPv6 avec zone
        "fc00::1",            # privée IPv6 (ULA)
        "::ffff:127.0.0.1",   # IPv4 locale encapsulée en IPv6
        "2001:db8::1",        # documentation IPv6
        "pas-une-adresse",    # pas une adresse IP
    ],
)
def test_adresses_non_publiques_refusees(adresse):
    """Adresses privées, locales, réservées, multicast ou invalides : refusées."""
    assert adresse_publique(adresse) is False


# --- resoudre (vraie fonction, getaddrinfo factice) --------------------------


def _info(famille, adresse):
    """Entrée getaddrinfo factice : (famille, type, proto, nom canonique, adresse socket)."""
    adresse_socket = (adresse, 0) if famille == socket.AF_INET else (adresse, 0, 0, 0)
    return (famille, socket.SOCK_STREAM, 6, "", adresse_socket)


def test_resoudre_sans_doublon_et_en_sock_stream(monkeypatch):
    """resoudre demande SOCK_STREAM sans port et renvoie les adresses sans doublon."""
    appels: list[tuple] = []

    async def _getaddrinfo(self, hote, port, *args, **kwargs):
        appels.append((hote, port, kwargs))
        return [
            _info(socket.AF_INET, "93.184.215.14"),
            _info(socket.AF_INET, "93.184.215.14"),
            _info(socket.AF_INET6, "2606:2800:21f:cb07::1"),
        ]

    monkeypatch.setattr(asyncio.base_events.BaseEventLoop, "getaddrinfo", _getaddrinfo)

    adresses = asyncio.run(resoudre_reel(DOMAINE))

    assert adresses == ["93.184.215.14", "2606:2800:21f:cb07::1"]
    assert appels == [(DOMAINE, None, {"type": socket.SOCK_STREAM})]


@pytest.mark.parametrize(
    "erreur",
    [socket.gaierror("nom inconnu"), UnicodeError("IDNA invalide")],
    ids=["gaierror", "unicode"],
)
def test_resoudre_convertit_les_erreurs_en_oserror(monkeypatch, erreur):
    """Nom inconnu (gaierror) ou mal formé (UnicodeError) : OSError."""

    async def _getaddrinfo(self, hote, port, *args, **kwargs):
        raise erreur

    monkeypatch.setattr(asyncio.base_events.BaseEventLoop, "getaddrinfo", _getaddrinfo)

    with pytest.raises(OSError):
        asyncio.run(resoudre_reel(DOMAINE))


def test_resoudre_trop_lent_leve_oserror(monkeypatch):
    """Une résolution plus lente que le délai (ramené à 0,01 s) lève OSError."""
    import pmescan.reseau as reseau

    monkeypatch.setattr(reseau, "_DELAI_RESOLUTION", 0.01)

    async def _getaddrinfo_lent(self, hote, port, *args, **kwargs):
        await asyncio.sleep(1)
        return [_info(socket.AF_INET, "93.184.215.14")]

    monkeypatch.setattr(asyncio.base_events.BaseEventLoop, "getaddrinfo", _getaddrinfo_lent)

    with pytest.raises(OSError):
        asyncio.run(resoudre_reel(DOMAINE))


# --- adresses_publiques et choisir_adresse -----------------------------------


def test_adresses_publiques_toutes_publiques(resolution_factice):
    """Toutes les adresses sont publiques : elles sont renvoyées telles quelles."""
    resolution_factice[:] = ["93.184.215.14", "2606:2800:21f:cb07::1"]

    assert asyncio.run(adresses_publiques(DOMAINE)) == [
        "93.184.215.14",
        "2606:2800:21f:cb07::1",
    ]


def test_adresses_publiques_refuse_un_melange(resolution_factice):
    """Une seule adresse interne suffit à refuser : CibleNonPublique liste les fautives."""
    resolution_factice[:] = ["93.184.215.14", "10.0.0.5"]

    with pytest.raises(CibleNonPublique) as erreur:
        asyncio.run(adresses_publiques(DOMAINE))

    assert erreur.value.hote == DOMAINE
    assert erreur.value.adresses == ["10.0.0.5"]


def test_adresses_publiques_ip_litterale_sans_resolution(resolution_factice):
    """Une IP littérale est vérifiée directement, sans résolution DNS."""
    resolution_factice.clear()  # toute résolution lèverait OSError

    assert asyncio.run(adresses_publiques("8.8.8.8")) == ["8.8.8.8"]
    with pytest.raises(CibleNonPublique):
        asyncio.run(adresses_publiques("127.0.0.1"))


def test_choisir_adresse_prefere_ipv4():
    """IPv4 d'abord ; sinon la première adresse ; None pour une liste vide."""
    assert choisir_adresse(["2606:2800:21f:cb07::1", "93.184.215.14"]) == "93.184.215.14"
    assert choisir_adresse(["2606:2800:21f:cb07::1"]) == "2606:2800:21f:cb07::1"
    assert choisir_adresse([]) is None


# --- hote_du_site --------------------------------------------------------------


@pytest.mark.parametrize(
    ("hote", "domaine", "attendu"),
    [
        ("exemple.sn", "exemple.sn", True),
        ("www.exemple.sn", "exemple.sn", True),
        ("EXEMPLE.SN.", "exemple.sn", True),
        ("exemple.sn", "www.exemple.sn", True),
        ("blog.www.exemple.sn", "www.exemple.sn", True),
        ("autre.sn", "exemple.sn", False),
        ("exemple.sn.attaquant.com", "exemple.sn", False),
        ("faux-exemple.sn", "exemple.sn", False),
        ("sn", "www.exemple.sn", False),
    ],
)
def test_hote_du_site(hote, domaine, attendu):
    """Domaine, sous-domaines et domaine nu (depuis www.) : du site ; le reste : tiers."""
    assert hote_du_site(hote, domaine) is attendu


# --- TransportGarde : vérifications avant envoi (respx) -----------------------


def _get(url, *, meme_site):
    """GET avec suivi des redirections à travers un client gardé."""

    async def _executer():
        async with client_garde(DOMAINE, meme_site=meme_site, follow_redirects=True) as client:
            return await client.get(url)

    return asyncio.run(_executer())


def test_redirection_vers_adresse_locale_bloquee(respx_mock):
    """Le site redirige vers http://127.0.0.1/ : la redirection est bloquée, jamais suivie."""
    respx_mock.get(f"https://{DOMAINE}/").mock(
        return_value=httpx.Response(302, headers={"location": "http://127.0.0.1/admin"})
    )
    route_interne = respx_mock.get("http://127.0.0.1/admin").mock(
        return_value=httpx.Response(200, text="interne")
    )

    with pytest.raises(RequeteBloquee):
        _get(f"https://{DOMAINE}/", meme_site=False)

    assert route_interne.called is False


def test_redirection_vers_nom_qui_pointe_en_interne_bloquee(respx_mock, monkeypatch):
    """Redirection vers un nom qui résout en 169.254.169.254 (métadonnées cloud) : bloquée."""
    import pmescan.reseau as reseau

    async def _resoudre(hote):
        return ["169.254.169.254"] if hote == "metadonnees.exemple.com" else ["93.184.215.14"]

    monkeypatch.setattr(reseau, "resoudre", _resoudre)
    respx_mock.get(f"https://{DOMAINE}/").mock(
        return_value=httpx.Response(
            302, headers={"location": "http://metadonnees.exemple.com/latest/"}
        )
    )
    route_interne = respx_mock.get("http://metadonnees.exemple.com/latest/").mock(
        return_value=httpx.Response(200)
    )

    with pytest.raises(RequeteBloquee):
        _get(f"https://{DOMAINE}/", meme_site=True)

    assert route_interne.called is False


def test_domaine_qui_pointe_en_interne_bloque(respx_mock, resolution_factice):
    """Le domaine lui-même résout en adresse privée : aucune requête ne part."""
    resolution_factice[:] = ["192.168.1.10"]
    route = respx_mock.get(f"https://{DOMAINE}/").mock(return_value=httpx.Response(200))

    with pytest.raises(RequeteBloquee):
        _get(f"https://{DOMAINE}/", meme_site=False)

    assert route.called is False


def test_meme_site_bloque_une_redirection_vers_un_tiers(respx_mock):
    """meme_site=True : une redirection vers un autre site n'est pas suivie."""
    respx_mock.get(f"https://{DOMAINE}/.env").mock(
        return_value=httpx.Response(302, headers={"location": "https://tiers.org/.env"})
    )
    route_tiers = respx_mock.get("https://tiers.org/.env").mock(
        return_value=httpx.Response(200, text="SECRET=1")
    )

    with pytest.raises(RequeteBloquee):
        _get(f"https://{DOMAINE}/.env", meme_site=True)

    assert route_tiers.called is False


def test_sans_meme_site_un_tiers_public_est_suivi(respx_mock):
    """meme_site=False (lecture passive) : une redirection vers un site public est suivie."""
    respx_mock.get(f"http://{DOMAINE}/").mock(
        return_value=httpx.Response(301, headers={"location": "https://tiers.org/"})
    )
    respx_mock.get("https://tiers.org/").mock(return_value=httpx.Response(200))

    reponse = _get(f"http://{DOMAINE}/", meme_site=False)

    assert reponse.status_code == 200
    assert str(reponse.url) == "https://tiers.org/"


def test_meme_site_suit_le_passage_au_www(respx_mock):
    """meme_site=True : exemple.com -> www.exemple.com reste sur le site, donc suivi."""
    respx_mock.get(f"https://{DOMAINE}/").mock(
        return_value=httpx.Response(301, headers={"location": f"https://www.{DOMAINE}/"})
    )
    respx_mock.get(f"https://www.{DOMAINE}/").mock(return_value=httpx.Response(200))

    assert _get(f"https://{DOMAINE}/", meme_site=True).status_code == 200


# --- TransportGarde : contrôle après connexion --------------------------------


class _FluxFactice:
    """Imite l'extension ``network_stream`` d'httpcore : seule ``server_addr`` est servie."""

    def __init__(self, adresse: str) -> None:
        self._adresse = adresse

    def get_extra_info(self, cle):
        return (self._adresse, 443) if cle == "server_addr" else None


class _TransportFactice(httpx.AsyncBaseTransport):
    """Transport interne factice : répond 200 en déclarant l'adresse jointe donnée."""

    def __init__(self, adresse_jointe: str) -> None:
        self._adresse = adresse_jointe

    async def handle_async_request(self, request):
        return httpx.Response(
            200, extensions={"network_stream": _FluxFactice(self._adresse)}
        )


@pytest.mark.parametrize(
    ("adresse_jointe", "bloquee"),
    [("127.0.0.1", True), ("10.1.2.3", True), (ADRESSE_PUBLIQUE_FACTICE, False)],
)
def test_adresse_jointe_controlee_apres_connexion(adresse_jointe, bloquee):
    """Le DNS a changé entre la vérification et la connexion : adresse jointe contrôlée."""
    transport = TransportGarde(DOMAINE, meme_site=True)
    transport._interne = _TransportFactice(adresse_jointe)

    async def _executer():
        async with httpx.AsyncClient(transport=transport) as client:
            return await client.get(f"https://{DOMAINE}/")

    if bloquee:
        with pytest.raises(RequeteBloquee):
            asyncio.run(_executer())
    else:
        assert asyncio.run(_executer()).status_code == 200


class _GestionnaireMuet(http.server.BaseHTTPRequestHandler):
    """Serveur local minimal : répond 200 « interne » et n'écrit aucun journal."""

    def do_GET(self):  # noqa: N802 - nom imposé par http.server
        corps = b"interne"
        self.send_response(200)
        self.send_header("Content-Length", str(len(corps)))
        self.end_headers()
        self.wfile.write(corps)

    def log_message(self, format, *args):  # noqa: A002 - signature imposée
        return


def test_dns_rebinding_reel_bloque(resolution_factice):
    """Vrai réseau local : la vérification DNS voit une adresse publique, mais la connexion
    atterrit sur 127.0.0.1. Le transport détecte l'adresse réellement jointe et bloque.
    """
    serveur = http.server.HTTPServer(("127.0.0.1", 0), _GestionnaireMuet)
    fil = threading.Thread(target=serveur.serve_forever, daemon=True)
    fil.start()
    try:
        port = serveur.server_address[1]
        # La garde croit que « localhost » est public ; le système le résout en 127.0.0.1.
        resolution_factice[:] = [ADRESSE_PUBLIQUE_FACTICE]

        async def _executer():
            async with client_garde("localhost", meme_site=True) as client:
                return await client.get(f"http://localhost:{port}/")

        with pytest.raises(RequeteBloquee):
            asyncio.run(_executer())
    finally:
        serveur.shutdown()
        serveur.server_close()


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
