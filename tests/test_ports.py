"""Tests hors-ligne de la vérification des ports TCP (mode actif).

Aucune socket réelle et aucune requête DNS réelle : on remplace
``VerificationPorts._resoudre`` par une fausse résolution (IP factice de documentation)
et ``asyncio.open_connection`` par une fausse coroutine pilotée par un ensemble de ports
« ouverts ». On vérifie aussi, via scanner(), que ce check intrusif ne s'exécute qu'à
partir du mode actif.
"""

import asyncio

import pytest

import pmescan.checks.ports as ports_module
import pmescan.scanner as scanner_module
from pmescan.checks.ports import _CONCURRENCE_MAX, _PORTS, VerificationPorts
from pmescan.modele import Cible, Gravite
from pmescan.scanner import scanner
from tests.conftest import (
    ADRESSE_FACTICE,
    ADRESSE_PUBLIQUE_FACTICE,
    faux_open_connection,
    faux_resoudre,
)

DOMAINE = "exemple.com"
# Adresse IPv6 publique (les plages de documentation 2001:db8:: sont refusées par la garde).
_IPV6_PUBLIQUE = "2606:2800:21f:cb07::1"


def _ouverture_avec_delai_depasse(ports_ouverts, en_delai_depasse):
    """Variante du helper partagé : les ports de ``en_delai_depasse`` lèvent TimeoutError."""
    ouvrir = faux_open_connection(ports_ouverts)

    async def _ouvrir(hote, port):
        if port in en_delai_depasse:
            raise TimeoutError("délai dépassé")
        return await ouvrir(hote, port)

    return _ouvrir


def _par_identifiant(resultats, identifiant):
    return next((r for r in resultats if r.identifiant == identifiant), None)


@pytest.fixture
def sans_dns(monkeypatch):
    """Remplace la résolution d'hôte par une IP factice : aucun accès au vrai DNS."""
    monkeypatch.setattr(VerificationPorts, "_resoudre", faux_resoudre())


def _executer(monkeypatch, ports_ouverts, *, en_delai_depasse=()):
    """Exécute la vérification des ports avec open_connection simulé."""
    monkeypatch.setattr(
        asyncio,
        "open_connection",
        _ouverture_avec_delai_depasse(ports_ouverts, en_delai_depasse),
    )
    cible = Cible(domaine=DOMAINE, mode="actif", autorisation=True)
    return asyncio.run(VerificationPorts().executer(cible))


# --- Port sensible ouvert ----------------------------------------------------


def test_port_mysql_ouvert_detecte(monkeypatch, sans_dns):
    """3306 ouvert (seul) produit port_ouvert_mysql CRITIQUE ; les autres ne sont pas émis."""
    resultats = _executer(monkeypatch, ports_ouverts={3306})

    mysql = _par_identifiant(resultats, "port_ouvert_mysql")
    assert mysql is not None
    assert mysql.reussi is False
    assert mysql.gravite is Gravite.CRITIQUE
    assert mysql.preuve == f"{DOMAINE}:3306"
    # La connexion vise l'adresse résolue une seule fois (IP factice), pas le nom.
    assert mysql.details["adresse"] == ADRESSE_FACTICE
    # Un port fermé ne doit pas apparaître.
    assert _par_identifiant(resultats, "port_ouvert_ssh") is None
    # Comme un port sensible est ouvert, on ne conclut pas « aucun port sensible ».
    assert _par_identifiant(resultats, "aucun_port_sensible") is None


def test_connexions_visent_l_adresse_resolue(monkeypatch, sans_dns):
    """Chaque tentative de connexion reçoit l'IP résolue, jamais le nom de domaine."""
    hotes_vises: set[str] = set()

    async def _ouvrir(hote, port):
        hotes_vises.add(hote)
        raise OSError("connexion refusée")

    monkeypatch.setattr(asyncio, "open_connection", _ouvrir)
    cible = Cible(domaine=DOMAINE, mode="actif", autorisation=True)
    asyncio.run(VerificationPorts().executer(cible))

    assert hotes_vises == {ADRESSE_FACTICE}


@pytest.mark.parametrize(
    ("port", "identifiant"), [(5900, "port_ouvert_vnc"), (445, "port_ouvert_smb")]
)
def test_vnc_et_smb_sont_critiques(monkeypatch, sans_dns, port, identifiant):
    """VNC (5900) et SMB (445) ouverts sont classés CRITIQUE."""
    resultats = _executer(monkeypatch, ports_ouverts={port})

    resultat = _par_identifiant(resultats, identifiant)
    assert resultat is not None
    assert resultat.reussi is False
    assert resultat.gravite is Gravite.CRITIQUE


def test_port_3000_est_web_3000_moyenne(monkeypatch, sans_dns):
    """Le port 3000 produit port_ouvert_web_3000 MOYENNE (et plus port_ouvert_grafana)."""
    resultats = _executer(monkeypatch, ports_ouverts={3000})

    resultat = _par_identifiant(resultats, "port_ouvert_web_3000")
    assert resultat is not None
    assert resultat.reussi is False
    assert resultat.gravite is Gravite.MOYENNE
    assert _par_identifiant(resultats, "port_ouvert_grafana") is None


# --- Ports attendus et aucun port sensible -----------------------------------


def test_aucun_port_sensible_quand_tout_ferme(monkeypatch, sans_dns):
    """Tous les ports fermés produisent uniquement aucun_port_sensible INFO réussi."""
    resultats = _executer(monkeypatch, ports_ouverts=set())

    assert len(resultats) == 1
    assert resultats[0].identifiant == "aucun_port_sensible"
    assert resultats[0].reussi is True
    assert resultats[0].gravite is Gravite.INFO


@pytest.mark.parametrize(
    ("port", "identifiant"), [(443, "port_ouvert_https"), (80, "port_ouvert_http")]
)
def test_ports_web_attendus_sont_info_reussis(monkeypatch, sans_dns, port, identifiant):
    """80 et 443 ouverts sont des ports web attendus : INFO réussi, sans pénalité."""
    resultats = _executer(monkeypatch, ports_ouverts={port})

    resultat = _par_identifiant(resultats, identifiant)
    assert resultat is not None
    assert resultat.reussi is True
    assert resultat.gravite is Gravite.INFO
    assert resultat.preuve == f"{DOMAINE}:{port}"
    # Seul un port attendu est ouvert : la conclusion reste « aucun port sensible ».
    assert _par_identifiant(resultats, "aucun_port_sensible") is not None


# --- Fermeture et concurrence ------------------------------------------------


def test_ecrivain_ferme_pour_un_port_ouvert(monkeypatch, sans_dns):
    """Pour chaque port ouvert, close() est appelé une fois sur l'écrivain."""
    ecrivains: list = []
    monkeypatch.setattr(
        asyncio, "open_connection", faux_open_connection({22, 3306}, ecrivains)
    )

    cible = Cible(domaine=DOMAINE, mode="actif", autorisation=True)
    asyncio.run(VerificationPorts().executer(cible))

    assert len(ecrivains) == 2
    assert all(ecrivain.fermetures == 1 for ecrivain in ecrivains)


def test_concurrence_ne_depasse_jamais_la_limite(monkeypatch, sans_dns):
    """Le nombre de connexions simultanées ne dépasse jamais _CONCURRENCE_MAX (20)."""
    assert _CONCURRENCE_MAX == 20
    # Le test n'a de sens que si plus de ports que la limite sont testés.
    assert len(_PORTS) > _CONCURRENCE_MAX
    compteur = {"en_cours": 0, "max": 0}

    async def _ouvrir(hote, port):
        compteur["en_cours"] += 1
        compteur["max"] = max(compteur["max"], compteur["en_cours"])
        try:
            # Laisse aux autres tâches le temps de démarrer en parallèle.
            await asyncio.sleep(0.01)
            raise OSError("connexion refusée")
        finally:
            compteur["en_cours"] -= 1

    monkeypatch.setattr(asyncio, "open_connection", _ouvrir)
    cible = Cible(domaine=DOMAINE, mode="actif", autorisation=True)
    asyncio.run(VerificationPorts().executer(cible))

    assert compteur["max"] <= _CONCURRENCE_MAX
    # Et les connexions sont bien parallélisées jusqu'à la limite.
    assert compteur["max"] == _CONCURRENCE_MAX


# --- Robustesse : délai dépassé et résolution --------------------------------


def test_timeout_gere_sans_exception(monkeypatch, sans_dns):
    """Un port en délai dépassé est traité comme fermé : aucune exception ne remonte."""
    resultats = _executer(monkeypatch, ports_ouverts=set(), en_delai_depasse={22, 3306})

    # Aucun port réputé ouvert : on retombe sur aucun_port_sensible.
    assert len(resultats) == 1
    assert resultats[0].identifiant == "aucun_port_sensible"
    assert resultats[0].reussi is True


def test_hote_introuvable_donne_un_seul_resultat(monkeypatch):
    """Résolution en échec : un seul ports_hote_introuvable INFO, aucune connexion tentée."""
    monkeypatch.setattr(VerificationPorts, "_resoudre", faux_resoudre(None))
    tentatives: list[int] = []

    async def _ouvrir(hote, port):
        tentatives.append(port)
        raise OSError("ne doit pas être appelé")

    monkeypatch.setattr(asyncio, "open_connection", _ouvrir)

    resultats = asyncio.run(
        VerificationPorts().executer(
            Cible(domaine="introuvable.invalid", mode="actif", autorisation=True)
        )
    )

    assert len(resultats) == 1
    assert resultats[0].identifiant == "ports_hote_introuvable"
    assert resultats[0].reussi is False
    assert resultats[0].gravite is Gravite.INFO
    assert resultats[0].preuve == "introuvable.invalid"
    assert tentatives == []


def test_resoudre_renvoie_none_si_nom_introuvable(resolution_factice):
    """Nom introuvable (la résolution lève OSError) : _resoudre renvoie None."""
    resolution_factice.clear()

    assert asyncio.run(VerificationPorts()._resoudre(DOMAINE)) is None


def test_resoudre_renvoie_la_premiere_adresse(resolution_factice):
    """_resoudre renvoie la première adresse publique résolue."""
    resolution_factice[:] = [ADRESSE_PUBLIQUE_FACTICE, "93.184.215.99"]

    assert asyncio.run(VerificationPorts()._resoudre(DOMAINE)) == ADRESSE_PUBLIQUE_FACTICE


def test_resoudre_prefere_ipv4(resolution_factice):
    """Le DNS renvoie IPv6 puis IPv4 : _resoudre choisit l'adresse IPv4."""
    resolution_factice[:] = [_IPV6_PUBLIQUE, ADRESSE_PUBLIQUE_FACTICE]

    assert asyncio.run(VerificationPorts()._resoudre(DOMAINE)) == ADRESSE_PUBLIQUE_FACTICE


def test_resoudre_ipv6_seule(resolution_factice):
    """Sans aucune adresse IPv4, _resoudre renvoie la première adresse IPv6."""
    resolution_factice[:] = [_IPV6_PUBLIQUE, "2606:2800:21f:cb07::2"]

    assert asyncio.run(VerificationPorts()._resoudre(DOMAINE)) == _IPV6_PUBLIQUE


def test_resoudre_delai_depasse_renvoie_none(monkeypatch):
    """Une résolution plus lente que le délai (ramené à 0,01 s) renvoie None, sans exception."""
    monkeypatch.setattr(ports_module, "_DELAI_CONNEXION", 0.01)

    async def _adresses_lentes(hote):
        await asyncio.sleep(1)
        return [ADRESSE_PUBLIQUE_FACTICE]

    monkeypatch.setattr(ports_module, "adresses_publiques", _adresses_lentes)

    assert asyncio.run(VerificationPorts()._resoudre(DOMAINE)) is None


@pytest.mark.parametrize(
    "adresses",
    [["127.0.0.1"], ["192.168.1.10"], [ADRESSE_PUBLIQUE_FACTICE, "10.0.0.5"]],
    ids=["boucle_locale", "reseau_prive", "publique_et_privee"],
)
def test_cible_non_publique_aucun_port_teste(monkeypatch, resolution_factice, adresses):
    """Garde réseau : une adresse non publique donne ports_cible_non_publique, sans connexion."""
    resolution_factice[:] = adresses
    tentatives: list[int] = []

    async def _ouvrir(hote, port):
        tentatives.append(port)
        raise OSError("ne doit pas être appelé")

    monkeypatch.setattr(ports_module.asyncio, "open_connection", _ouvrir)
    cible = Cible(domaine=DOMAINE, mode="actif", autorisation=True)

    resultats = asyncio.run(VerificationPorts().executer(cible))

    assert [r.identifiant for r in resultats] == ["ports_cible_non_publique"]
    assert resultats[0].reussi is False
    assert resultats[0].gravite is Gravite.INFO
    assert tentatives == []


def test_ip_figee_non_publique_refusee(monkeypatch):
    """Cible.ip privée (posée à la main via l'API Python) : aucun port n'est testé."""
    tentatives: list[int] = []

    async def _ouvrir(hote, port):
        tentatives.append(port)
        raise OSError("ne doit pas être appelé")

    monkeypatch.setattr(ports_module.asyncio, "open_connection", _ouvrir)
    cible = Cible(domaine=DOMAINE, ip="127.0.0.1", mode="actif", autorisation=True)

    resultats = asyncio.run(VerificationPorts().executer(cible))

    assert [r.identifiant for r in resultats] == ["ports_cible_non_publique"]
    assert tentatives == []


# --- Défense en profondeur : appel direct sans autorisation ------------------


@pytest.mark.parametrize("mode", ["actif", "agressif"])
def test_appel_direct_sans_autorisation_ne_fait_rien(monkeypatch, mode):
    """executer() appelé DIRECTEMENT sans autorisation : [] sans résolution ni connexion."""
    compteur = {"resolutions": 0, "connexions": 0}

    async def _faux_resoudre(self, hote):
        compteur["resolutions"] += 1
        return ADRESSE_FACTICE

    async def _fausse_connexion(hote, port):
        compteur["connexions"] += 1
        raise OSError("connexion refusée")

    monkeypatch.setattr(VerificationPorts, "_resoudre", _faux_resoudre)
    monkeypatch.setattr(asyncio, "open_connection", _fausse_connexion)

    resultats = asyncio.run(VerificationPorts().executer(Cible(domaine=DOMAINE, mode=mode)))

    assert resultats == []
    assert compteur == {"resolutions": 0, "connexions": 0}


# --- Activation par mode via scanner() ---------------------------------------


def test_scanner_passif_n_execute_pas_les_ports(monkeypatch, sans_dns):
    """En mode passif, le check « ports » (niveau actif) n'est pas exécuté."""
    monkeypatch.setattr(scanner_module, "VERIFICATIONS", [VerificationPorts()])
    # open_connection ne doit jamais être appelé ; on le remplace quand même par sûreté.
    monkeypatch.setattr(asyncio, "open_connection", faux_open_connection({3306}))
    cible = Cible(domaine=DOMAINE, mode="passif")

    resultats = asyncio.run(scanner(cible))

    assert resultats == []


def test_scanner_actif_execute_les_ports(monkeypatch, sans_dns):
    """En mode actif, le check « ports » s'exécute et détecte le port ouvert simulé."""
    monkeypatch.setattr(scanner_module, "VERIFICATIONS", [VerificationPorts()])
    monkeypatch.setattr(asyncio, "open_connection", faux_open_connection({3306}))
    cible = Cible(domaine=DOMAINE, mode="actif", autorisation=True)

    resultats = asyncio.run(scanner(cible))

    identifiants = {r.identifiant for r in resultats}
    assert "port_ouvert_mysql" in identifiants


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
