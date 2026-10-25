# pmescan

> Scanner de sécurité pour PME francophones. Un site web analysé, un rapport PDF en
> français clair — compréhensible par un gérant, pas seulement par un expert.

![Licence](https://img.shields.io/badge/licence-MIT-green)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![Statut](https://img.shields.io/badge/statut-en%20d%C3%A9veloppement-orange)

---

## Pourquoi pmescan ?

Les PME ont un site web mais rarement une équipe sécurité. Les outils existants
(Mozilla Observatory, Nuclei, SSL Labs) sont en anglais, techniques et illisibles pour
un dirigeant. pmescan traduit chaque faille en **risque métier**, en **français**, avec
une **action priorisée**.

| Au lieu de… | pmescan dit… |
|---|---|
| `DMARC record not found` | « N'importe qui peut envoyer des e-mails en se faisant passer pour vous. » |
| `TLS 1.0 enabled` | « Votre site utilise un chiffrement obsolète qu'un attaquant peut casser. » |
| `Port 3306 open` | « Votre base de données est accessible depuis Internet. À fermer en urgence. » |

## Fonctionnalités

- **TLS / certificat** — expiration, chaîne, TLS 1.0/1.1, chiffrements faibles, redirection HTTP→HTTPS.
- **En-têtes HTTP** — HSTS, CSP, X-Frame-Options, cookies (`Secure`, `HttpOnly`, `SameSite`), fuite de version.
- **DNS / e-mail** — SPF, DMARC, DKIM, MX, DNSSEC. *(Le plus utile pour une PME.)*
- **CMS** — détection WordPress/Joomla/Drupal/PrestaShop + CVE connues (API OSV).
- **Ports exposés** — ~30 ports critiques (bases de données, RDP, etc.).
- **Fichiers sensibles** — `/.git/`, `/.env`, `backup.zip`, listing de répertoires.
- **Rapport PDF** — note A→F, risque métier, qui corrige, effort estimé, encadré légal.

## Installation

```bash
pip install pmescan
```

## Démarrage rapide

```bash
# Scan passif + rapport PDF en français
pmescan exemple.sn --pdf

# Sortie JSON (intégration, script, CI)
pmescan exemple.sn --json
```

Exemple de sortie :

```
  pmescan v1.0 — scan de exemple.sn (mode passif)

  [✓] TLS / certificat ......... terminé (2 problèmes)
  [✓] En-têtes HTTP ............ terminé (3 problèmes)
  [✓] DNS / e-mail ............. terminé (1 problème critique)
  [✓] Détection CMS ........... WordPress 6.1 (obsolète)
  [✓] Fichiers exposés ........ terminé (0 problème)

  Note globale : D

  Rapport PDF écrit : rapport-exemple.pdf
```

## Les trois modes

| Mode | Flag | Ce qu'il fait | Autorisation |
|---|---|---|---|
| **Passif** | *(défaut)* | Lit seulement ce que le site publie. | Non |
| **Actif** | `--actif` | Teste des ports critiques et chemins sensibles. | Oui |
| **Agressif** | `--agressif` | Sollicite activement la cible. | Oui, écrite |

> ⚠️ Les modes actif et agressif ne s'utilisent **que** sur une cible dont vous êtes
> propriétaire ou pour laquelle vous détenez une autorisation. Lire
> **[README-mode-agressif.md](README-mode-agressif.md)** avant de les utiliser.

## Le rapport PDF

- **Page 1** — note globale A→F, résumé en 3 phrases, 3 actions les plus urgentes.
- **Fiches** — une par problème : risque simple, gravité, qui corrige, effort estimé.
- **Annexe technique** — détails bruts pour le prestataire.
- **Encadré légal** — loi sénégalaise 2008-12 sur les données personnelles + CDP.

## Codes de sortie

| Code | Signification |
|---|---|
| `0` | Scan réussi, aucune faille critique. |
| `1` | Scan réussi, au moins une faille critique. |
| `2` | Erreur (cible injoignable, DNS invalide). |
| `3` | Refus (mode intrusif sans flag d'autorisation). |

## Architecture

Le projet est modulaire : chaque vérification est indépendante et renvoie le même type
d'objet `Resultat`. Les textes vulgarisés sont dans des fichiers YAML, séparés du code,
pour faciliter la relecture et la traduction. Détails dans
**[03-CONCEPTION.md](03-CONCEPTION.md)**.

Tout le code (variables, fonctions, commentaires) est **en français**.

## Documentation du projet

| Fichier | Contenu |
|---|---|
| [01-VISION.md](01-VISION.md) | À quoi sert le projet, pour qui, objectifs. |
| [02-UTILISATION.md](02-UTILISATION.md) | Comment on l'utilise au quotidien. |
| [03-CONCEPTION.md](03-CONCEPTION.md) | Architecture, stack, modèle de données. |
| [04-ETAPES.md](04-ETAPES.md) | Feuille de route de construction en 4 semaines. |
| [README-mode-agressif.md](README-mode-agressif.md) | Cadre légal et usage du mode agressif. |

## Avertissement légal

pmescan est un outil **défensif**. Le mode passif ne lit que des informations publiques.
Les modes actif et agressif sollicitent la cible et ne doivent être utilisés qu'avec
autorisation. Un usage non autorisé peut tomber sous la loi sénégalaise 2008-11 sur la
cybercriminalité (et ses équivalents : art. 323-1 du Code pénal français, CFAA aux USA).
**La responsabilité de disposer des autorisations incombe à l'utilisateur.**

## Contribuer

Les contributions sont bienvenues, y compris non techniques (améliorer les explications
en français dans `i18n/fr.yaml`, traduire en wolof). Voir `CONTRIBUTING.md`.

## Licence

MIT — voir [LICENSE](LICENSE).
