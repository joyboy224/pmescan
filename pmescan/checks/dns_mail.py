"""Vérification DNS et messagerie : SPF, DMARC, DKIM, MX, DNSSEC via dnspython."""

import dns.asyncresolver
import dns.exception
import dns.resolver

from pmescan.checks.base import Verification
from pmescan.modele import Cible, Gravite, Resultat

# Sélecteurs DKIM les plus répandus : on les teste en « meilleur effort », car le
# nom du sélecteur est libre et ne se devine pas de façon fiable.
_SELECTEURS_DKIM: tuple[str, ...] = (
    "default",
    "google",
    "selector1",
    "selector2",
    "k1",
    "dkim",
    "mail",
    "s1",
    "s2",
    "mandrill",
)


class VerificationDnsMail(Verification):
    """Analyse les enregistrements DNS liés à la messagerie et à l'authenticité."""

    nom = "dns_mail"
    niveau_minimum = "passif"

    async def executer(self, cible: Cible) -> list[Resultat]:
        resultats: list[Resultat] = []
        # On interroge d'abord les MX : cela sert aussi à détecter un domaine inexistant.
        mx, statut_mx = await self._resoudre(cible.domaine, "MX")
        if statut_mx == "erreur":
            return [self._resultat_info("dns_erreur", cible.domaine, "erreur de résolution DNS")]
        if statut_mx == "introuvable":
            return [
                self._resultat_info("dns_domaine_introuvable", cible.domaine, "domaine inexistant")
            ]

        resultats.append(self._analyser_mx(cible.domaine, mx))
        resultats.append(await self._analyser_spf(cible.domaine))
        resultats.append(await self._analyser_dmarc(cible.domaine))
        resultats.append(await self._analyser_dkim(cible.domaine))
        resultats.append(await self._analyser_dnssec(cible.domaine))
        return resultats

    async def _resoudre(self, nom: str, type_enreg: str) -> tuple[list[str], str]:
        """Interroge le DNS et renvoie (enregistrements, statut).

        Statuts possibles : ``ok`` (au moins un enregistrement), ``absent`` (aucun
        enregistrement de ce type), ``introuvable`` (le nom n'existe pas) ou
        ``erreur`` (délai dépassé ou serveur injoignable). Aucune exception ne sort.
        """
        try:
            reponse = await dns.asyncresolver.resolve(nom, type_enreg)
        except dns.resolver.NXDOMAIN:
            return [], "introuvable"
        except dns.resolver.NoAnswer:
            return [], "absent"
        except (dns.resolver.NoNameservers, dns.exception.Timeout, dns.exception.DNSException):
            return [], "erreur"
        return [donnee.to_text() for donnee in reponse], "ok"

    def _analyser_mx(self, domaine: str, enregistrements: list[str]) -> Resultat:
        """Signale l'absence de serveur de messagerie (enregistrement MX)."""
        if enregistrements:
            return Resultat(
                identifiant="mx_present",
                gravite=Gravite.INFO,
                reussi=True,
                preuve=", ".join(enregistrements),
            )
        return Resultat(
            identifiant="mx_absent",
            gravite=Gravite.FAIBLE,
            reussi=False,
            details={"domaine": domaine},
        )

    async def _analyser_spf(self, domaine: str) -> Resultat:
        """Vérifie la présence d'un enregistrement SPF (TXT v=spf1)."""
        txt, statut = await self._resoudre(domaine, "TXT")
        if statut == "erreur":
            return self._resultat_info("dns_erreur", domaine, "erreur de résolution SPF")
        enregistrements_spf = [t for t in txt if "v=spf1" in t.lower()]
        if enregistrements_spf:
            return Resultat(
                identifiant="spf_present",
                gravite=Gravite.INFO,
                reussi=True,
                preuve=enregistrements_spf[0].strip('"'),
            )
        return Resultat(
            identifiant="spf_absent",
            gravite=Gravite.MOYENNE,
            reussi=False,
            details={"domaine": domaine},
        )

    async def _analyser_dmarc(self, domaine: str) -> Resultat:
        """Vérifie la présence d'une politique DMARC (_dmarc TXT v=DMARC1)."""
        nom = f"_dmarc.{domaine}"
        txt, statut = await self._resoudre(nom, "TXT")
        if statut == "erreur":
            return self._resultat_info("dns_erreur", domaine, "erreur de résolution DMARC")
        enregistrements_dmarc = [t for t in txt if "v=dmarc1" in t.lower()]
        if enregistrements_dmarc:
            return Resultat(
                identifiant="dmarc_present",
                gravite=Gravite.INFO,
                reussi=True,
                preuve=enregistrements_dmarc[0].strip('"'),
            )
        return Resultat(
            identifiant="dmarc_absent",
            gravite=Gravite.ELEVEE,
            reussi=False,
            details={"domaine": domaine},
        )

    async def _analyser_dkim(self, domaine: str) -> Resultat:
        """Cherche une clé DKIM sur les sélecteurs courants (meilleur effort)."""
        for selecteur in _SELECTEURS_DKIM:
            nom = f"{selecteur}._domainkey.{domaine}"
            txt, statut = await self._resoudre(nom, "TXT")
            if statut != "ok":
                continue
            valeurs = " ".join(txt).lower()
            if "v=dkim1" in valeurs or "p=" in valeurs:
                return Resultat(
                    identifiant="dkim_present",
                    gravite=Gravite.INFO,
                    reussi=True,
                    preuve=selecteur,
                    details={"selecteur": selecteur},
                )
        # Absence non concluante : le sélecteur réel peut simplement être inconnu.
        # On reste en INFO (pénalité nulle) pour ne pas sanctionner un faux positif.
        return Resultat(
            identifiant="dkim_absent",
            gravite=Gravite.INFO,
            reussi=False,
            details={"domaine": domaine, "selecteurs_testes": list(_SELECTEURS_DKIM)},
        )

    async def _analyser_dnssec(self, domaine: str) -> Resultat:
        """Vérifie la présence de clés DNSSEC (enregistrement DNSKEY) sur le domaine."""
        cles, statut = await self._resoudre(domaine, "DNSKEY")
        if statut == "erreur":
            return self._resultat_info("dns_erreur", domaine, "erreur de résolution DNSSEC")
        if cles:
            return Resultat(
                identifiant="dnssec_present",
                gravite=Gravite.INFO,
                reussi=True,
                preuve=f"{len(cles)} clé(s) DNSKEY",
            )
        return Resultat(
            identifiant="dnssec_absent",
            gravite=Gravite.FAIBLE,
            reussi=False,
            details={"domaine": domaine},
        )

    def _resultat_info(self, identifiant: str, domaine: str, message: str) -> Resultat:
        """Fabrique un résultat d'information (erreur DNS ou domaine introuvable)."""
        return Resultat(
            identifiant=identifiant,
            gravite=Gravite.INFO,
            reussi=False,
            preuve=message,
            details={"domaine": domaine},
        )
