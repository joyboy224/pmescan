"""Tests hors-ligne de la vérification DNS et messagerie (SPF, DMARC, MX, DKIM, DNSSEC).

Aucun test ne touche au réseau : on remplace ``dns.asyncresolver.resolve`` par une
fausse fonction asynchrone qui rejoue des réponses décidées par le test, ou qui lève
les exceptions dnspython attendues (NXDOMAIN, Timeout, etc.).
"""

import asyncio

import dns.asyncresolver
import dns.exception
import dns.resolver
import pytest

from pmescan.checks.dns_mail import VerificationDnsMail
from pmescan.modele import Cible, Gravite

DOMAINE = "exemple.com"


class FauxEnreg:
    """Imite un enregistrement dnspython : expose seulement ``to_text()``."""

    def __init__(self, texte: str) -> None:
        self._texte = texte

    def to_text(self) -> str:
        return self._texte


def _faux_resolver(reponses: dict):
    """Fabrique une fausse coroutine ``resolve`` pilotée par ``reponses``.

    ``reponses`` associe une clé ``(nom, type)`` soit à une liste de textes
    d'enregistrements, soit à une exception (classe ou instance) à lever. Toute
    clé absente renvoie « aucune réponse » (NoAnswer), ce qui simule un
    enregistrement absent sans que le nom soit introuvable.
    """

    async def _resolve(nom, type_enreg, *args, **kwargs):
        valeur = reponses.get((nom, type_enreg), dns.resolver.NoAnswer)
        if isinstance(valeur, type) and issubclass(valeur, BaseException):
            raise valeur()
        if isinstance(valeur, BaseException):
            raise valeur
        return [FauxEnreg(texte) for texte in valeur]

    return _resolve


def _installer(monkeypatch, reponses: dict) -> None:
    """Remplace le resolver asynchrone dnspython par le faux resolver du test."""
    monkeypatch.setattr(dns.asyncresolver, "resolve", _faux_resolver(reponses))


def _executer(reponses: dict, monkeypatch):
    """Installe le faux resolver puis exécute la vérification sur exemple.com."""
    _installer(monkeypatch, reponses)
    cible = Cible(domaine=DOMAINE, mode="passif")
    return asyncio.run(VerificationDnsMail().executer(cible))


def _par_identifiant(resultats, identifiant):
    return next((r for r in resultats if r.identifiant == identifiant), None)


# Jeu de réponses « saines » : MX, SPF, DMARC, DKIM et DNSSEC tous présents.
def _reponses_saines() -> dict:
    return {
        (DOMAINE, "MX"): ["10 mail.exemple.com."],
        (DOMAINE, "TXT"): ['"v=spf1 include:_spf.exemple.com ~all"'],
        (f"_dmarc.{DOMAINE}", "TXT"): ['"v=DMARC1; p=reject; rua=mailto:a@exemple.com"'],
        (f"default._domainkey.{DOMAINE}", "TXT"): ['"v=DKIM1; k=rsa; p=MIGf..."'],
        (DOMAINE, "DNSKEY"): ["257 3 13 clefpublique=="],
    }


# --- MX ----------------------------------------------------------------------


def test_mx_present_est_reussi(monkeypatch):
    """Un domaine avec enregistrement MX produit mx_present réussi."""
    resultats = _executer(_reponses_saines(), monkeypatch)
    resultat = _par_identifiant(resultats, "mx_present")
    assert resultat is not None
    assert resultat.reussi is True
    assert "mail.exemple.com" in resultat.preuve


def test_mx_absent_detecte(monkeypatch):
    """Sans MX (réponse vide), on signale mx_absent en gravité faible, non réussi."""
    reponses = _reponses_saines()
    del reponses[(DOMAINE, "MX")]  # (DOMAINE, "MX") retombe sur NoAnswer -> absent
    resultats = _executer(reponses, monkeypatch)
    resultat = _par_identifiant(resultats, "mx_absent")
    assert resultat is not None
    assert resultat.reussi is False
    assert resultat.gravite is Gravite.FAIBLE


# --- SPF ----------------------------------------------------------------------


def test_spf_present_est_reussi(monkeypatch):
    """Un TXT v=spf1 produit spf_present réussi, guillemets retirés."""
    resultats = _executer(_reponses_saines(), monkeypatch)
    resultat = _par_identifiant(resultats, "spf_present")
    assert resultat is not None
    assert resultat.reussi is True
    assert resultat.preuve.startswith("v=spf1")


def test_spf_absent_detecte(monkeypatch):
    """Sans TXT SPF, on signale spf_absent en gravité moyenne."""
    reponses = _reponses_saines()
    del reponses[(DOMAINE, "TXT")]
    resultats = _executer(reponses, monkeypatch)
    resultat = _par_identifiant(resultats, "spf_absent")
    assert resultat is not None
    assert resultat.reussi is False
    assert resultat.gravite is Gravite.MOYENNE


# --- DMARC --------------------------------------------------------------------


def test_dmarc_present_est_reussi(monkeypatch):
    """Un TXT v=DMARC1 sur _dmarc produit dmarc_present réussi."""
    resultats = _executer(_reponses_saines(), monkeypatch)
    resultat = _par_identifiant(resultats, "dmarc_present")
    assert resultat is not None
    assert resultat.reussi is True
    assert "DMARC1" in resultat.preuve


def test_dmarc_absent_detecte(monkeypatch):
    """Sans politique DMARC, on signale dmarc_absent en gravité élevée."""
    reponses = _reponses_saines()
    del reponses[(f"_dmarc.{DOMAINE}", "TXT")]
    resultats = _executer(reponses, monkeypatch)
    resultat = _par_identifiant(resultats, "dmarc_absent")
    assert resultat is not None
    assert resultat.reussi is False
    assert resultat.gravite is Gravite.ELEVEE


# --- DKIM ---------------------------------------------------------------------


def test_dkim_present_est_reussi(monkeypatch):
    """Une clé v=DKIM1 sur le sélecteur « default » produit dkim_present réussi."""
    resultats = _executer(_reponses_saines(), monkeypatch)
    resultat = _par_identifiant(resultats, "dkim_present")
    assert resultat is not None
    assert resultat.reussi is True
    assert resultat.details["selecteur"] == "default"


def test_dkim_absent_detecte(monkeypatch):
    """Aucun sélecteur DKIM connu ne répond -> dkim_absent en gravité INFO.

    L'absence DKIM n'est pas concluante (le sélecteur réel peut être inconnu) :
    le check reste donc en INFO pour ne pas sanctionner un faux positif. Le
    résultat demeure non réussi (reussi=False).
    """
    reponses = _reponses_saines()
    del reponses[(f"default._domainkey.{DOMAINE}", "TXT")]
    resultats = _executer(reponses, monkeypatch)
    resultat = _par_identifiant(resultats, "dkim_absent")
    assert resultat is not None
    assert resultat.reussi is False
    assert resultat.gravite is Gravite.INFO


# --- DNSSEC -------------------------------------------------------------------


def test_dnssec_present_est_reussi(monkeypatch):
    """Des enregistrements DNSKEY produisent dnssec_present réussi."""
    resultats = _executer(_reponses_saines(), monkeypatch)
    resultat = _par_identifiant(resultats, "dnssec_present")
    assert resultat is not None
    assert resultat.reussi is True


def test_dnssec_absent_detecte(monkeypatch):
    """Sans DNSKEY, on signale dnssec_absent en gravité faible."""
    reponses = _reponses_saines()
    del reponses[(DOMAINE, "DNSKEY")]
    resultats = _executer(reponses, monkeypatch)
    resultat = _par_identifiant(resultats, "dnssec_absent")
    assert resultat is not None
    assert resultat.reussi is False
    assert resultat.gravite is Gravite.FAIBLE


# --- Cas d'erreur DNS ---------------------------------------------------------


def test_erreur_dns_sur_mx_renvoie_info_sans_exception(monkeypatch):
    """Un délai dépassé sur la requête MX renvoie dns_erreur (INFO) sans lever."""
    reponses = {(DOMAINE, "MX"): dns.exception.Timeout}
    resultats = _executer(reponses, monkeypatch)
    assert len(resultats) == 1
    resultat = resultats[0]
    assert resultat.identifiant == "dns_erreur"
    assert resultat.gravite is Gravite.INFO
    assert resultat.reussi is False


def test_domaine_introuvable_renvoie_info(monkeypatch):
    """Un NXDOMAIN sur la requête MX renvoie dns_domaine_introuvable (INFO)."""
    reponses = {(DOMAINE, "MX"): dns.resolver.NXDOMAIN}
    resultats = _executer(reponses, monkeypatch)
    assert len(resultats) == 1
    resultat = resultats[0]
    assert resultat.identifiant == "dns_domaine_introuvable"
    assert resultat.gravite is Gravite.INFO
    assert resultat.reussi is False


def test_erreur_dns_sur_serveur_injoignable(monkeypatch):
    """Un serveur de noms injoignable (NoNameservers) est traité comme une erreur DNS."""
    reponses = {(DOMAINE, "MX"): dns.resolver.NoNameservers}
    resultats = _executer(reponses, monkeypatch)
    assert len(resultats) == 1
    assert resultats[0].identifiant == "dns_erreur"


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
