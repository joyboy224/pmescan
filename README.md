# pmescan

> Scanner de sécurité pour PME francophones. On analyse un site web et on obtient un
> rapport en français clair, lisible par un gérant et pas seulement par un expert.

![Licence](https://img.shields.io/badge/licence-MIT-green)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![Statut](https://img.shields.io/badge/statut-alpha-orange)

---

## Pourquoi pmescan ?

Les PME ont un site web, mais rarement une équipe sécurité. Les outils existants
(Mozilla Observatory, Nuclei, SSL Labs) sont en anglais, techniques et peu lisibles pour
un dirigeant. pmescan traduit chaque faille en **risque métier**, en **français**, et
propose une **action priorisée**.

| Au lieu de… | pmescan dit… |
|---|---|
| `DMARC record not found` | « N'importe qui peut envoyer des e-mails en se faisant passer pour votre entreprise. » |
| `TLS 1.0 enabled` | « Votre site accepte un chiffrement ancien, que l'on sait aujourd'hui contourner. » |
| `Port 3306 open` | « Votre base de données est joignable depuis Internet. » |

## Ce que pmescan vérifie

| Vérification | Mode | Détail |
|---|---|---|
| **TLS / certificat** | passif | Expiration, protocoles obsolètes (SSL, TLS 1.0/1.1), chiffrements faibles, redirection HTTP vers HTTPS. |
| **En-têtes HTTP** | passif | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, attributs des cookies, version du serveur divulguée. |
| **DNS / e-mail** | passif | SPF, DMARC, DKIM (sélecteurs courants), MX, DNSSEC. |
| **CMS** | passif + actif | WordPress, Joomla, Drupal et PrestaShop, avec signalement des branches qui ne sont plus maintenues. En mode actif, s'y ajoutent les fichiers de version, XML-RPC et l'énumération des comptes WordPress. |
| **Failles connues (CVE)** | option | Interrogation de la base publique OSV, seulement avec `--verifier-cve`. |
| **Fichiers exposés** | actif | `/.git/`, `/.env`, sauvegardes, `phpinfo`, listing de répertoire. |
| **Ports** | actif | 30 ports testés, dont 28 sensibles (bases de données, accès distant, administration). Les ports web 80 et 443 sont considérés comme normaux. |

## Installation

pmescan demande Python 3.11 ou plus récent.

```bash
git clone <url-du-depot> pmescan
cd pmescan
python -m venv .venv
.venv/bin/pip install .          # Windows : .venv\Scripts\pip install .
```

Le rapport **PDF** passe par [WeasyPrint](https://doc.courtbouillon.org/weasyprint/stable/first_steps.html),
qui a besoin des bibliothèques système Pango et GTK. Elles sont simples à installer
sous Linux et macOS. Sous Windows, le plus simple est d'utiliser WSL. Sans ces
bibliothèques, les sorties texte et JSON fonctionnent quand même.

## Démarrage rapide

```bash
# Scan passif, résultat dans le terminal
pmescan scan exemple.sn

# Rapport PDF en français (défaut : rapport-exemple.sn.pdf)
pmescan scan exemple.sn --pdf

# Sortie JSON, pour un script ou une intégration continue
pmescan scan exemple.sn --json
```

Exemple de sortie texte (abrégée) :

```
$ pmescan scan exemple.sn
[OK] tls_certificat_valide (info)
[OK] tls_protocoles_sains (info)
[PROBLEME] tls_redirection_absente (moyenne)
[PROBLEME] entete_hsts_absent (moyenne)
[PROBLEME] entete_csp_absent (moyenne)
[OK] entete_x_frame_options_present (info)
[PROBLEME] entete_permissions_policy_absent (faible)
[OK] mx_present (info)
[OK] spf_present (info)
[PROBLEME] dmarc_absent (elevee)
[OK] cms_detecte (info)
Note globale : D (47/100)
```

Forme de la sortie JSON :

```json
{
  "note": "D",
  "score": 47,
  "resultats": [
    {
      "identifiant": "dmarc_absent",
      "gravite": "elevee",
      "reussi": false,
      "preuve": "",
      "details": {}
    }
  ]
}
```

Le terminal et le JSON affichent les **identifiants** techniques. Les explications en
français (titre, risque, qui corrige, effort, action) sont dans le **rapport PDF**.

## Options de `pmescan scan`

| Option | Effet |
|---|---|
| `--mode passif\|actif\|agressif` | Niveau d'analyse. Défaut : `passif`. |
| `--jai-l-autorisation` | **Obligatoire** pour les modes `actif` et `agressif`. |
| `--json` | Sortie JSON `{note, score, resultats}`. |
| `--pdf` | Écrit un rapport PDF en français. |
| `--sortie <fichier>` | Chemin du PDF. Défaut : `rapport-<domaine>.pdf`. |
| `--verifier-cve` | Interroge la base publique OSV pour les failles connues du CMS (voir « Vie privée »). |

Le domaine se donne seul : `exemple.sn` ou `www.exemple.sn`, sans `https://`, chemin ni
port. Il est mis en minuscules, et un nom accentué est converti en sa forme ASCII selon
la norme actuelle (UTS 46) : `café.fr` devient `xn--caf-dma.fr`. Une adresse IPv4 écrite
sous sa forme habituelle (`192.0.2.10`) est acceptée. Les adresses IPv6 ne sont pas encore
prises en charge. Un domaine invalide est refusé avec le code 2.

`pmescan --version` affiche la version.

## Modes actif et agressif

> ⚠️ Ces modes **sollicitent activement la cible** : chemins sensibles, fichiers de
> version, connexions TCP. Ne les utilisez que sur un site dont vous êtes propriétaire,
> ou pour lequel vous avez une **autorisation écrite** de son propriétaire.

```bash
pmescan scan exemple.sn --mode actif --jai-l-autorisation
```

- Sans `--jai-l-autorisation`, la commande refuse **avant toute requête** et se
  termine avec le code `3`.
- Chaque scan autorisé est noté dans le journal local `~/.pmescan/consent.log`.
- En version 0.1, le mode `agressif` fait la même chose que le mode `actif` : il est
  réservé à de futures vérifications plus intrusives.

### Requêtes envoyées à la cible

En plus des vérifications passives, le mode actif fait les requêtes suivantes :

- **Fichiers sensibles** : `/.git/HEAD`, `/.env`, `/backup.zip`, `/phpinfo.php`, et la
  racine du site pour repérer un listing de répertoire. Soit 5 requêtes HTTP.
- **Fichiers de version du CMS** : au plus 7 requêtes HTTP, et seulement si la page
  d'accueil ne suffit pas à reconnaître le CMS. pmescan demande d'abord une adresse
  aléatoire inexistante. Si elle répond « 200 », le site répond 200 à tout, et pmescan
  s'arrête là. Sinon, il demande `readme.html`, `CHANGELOG.txt`, `core/CHANGELOG.txt`,
  le manifeste Joomla et `/admin/`.
- **WordPress uniquement** : `xmlrpc.php` et `/?author=1`, pour repérer la page XML-RPC et
  l'énumération des comptes. Soit 2 requêtes HTTP.
- **Ports TCP** : une tentative de connexion sur 30 ports connus. Aucune donnée n'est
  envoyée après l'ouverture : la connexion est fermée tout de suite.

Garde-fous intégrés : au plus **20 connexions simultanées**, **2 secondes** maximum par
tentative, **une seule tentative** par port. Aucune tentative de mot de passe, aucun envoi
de formulaire, aucune exploitation de faille.

Le scan reste léger, mais il laisse des traces : la cible peut voir ces requêtes dans
ses journaux, et un pare-feu peut bloquer votre adresse IP.

### Journal de consentement

Chaque scan autorisé ajoute une ligne au fichier `~/.pmescan/consent.log`, **avant** le
début du scan. Chaque ligne contient trois champs séparés par des tabulations :
l'horodatage UTC, le domaine et le mode.

```
2026-10-25T15:18:33+00:00	exemple.sn	actif
```

Ce journal reste sur votre machine : il n'est envoyé nulle part. Pour le déplacer, réglez
la variable d'environnement `PMESCAN_DOSSIER`. Si le fichier ne peut pas être écrit,
pmescan affiche un avertissement et poursuit le scan.

## Le rapport PDF

- **Page 1** : note globale de A à F, résumé en 3 phrases, les 3 actions les plus
  urgentes.
- **Fiches** : une par problème, avec le risque expliqué simplement, la gravité, qui
  doit corriger (hébergeur, développeur ou gérant) et l'effort estimé.
- **Annexe technique** : identifiants et preuves brutes, pour le prestataire.
- **Rappel légal** : loi sénégalaise n° 2008-12 sur les données personnelles et rôle de
  la CDP.

## Notation

Chaque problème non résolu retire des points à un score de départ de 100 :

| Gravité | Pénalité |
|---|---|
| critique | 40 |
| élevée | 20 |
| moyenne | 10 |
| faible | 3 |
| info | 0 |

Le score reste toujours entre 0 et 100. Un même défaut ne coûte des points qu'une
fois : trois cookies non sécurisés comptent comme un seul problème. En revanche, deux
ports sensibles différents restent deux problèmes distincts.

| Lettre | Score |
|---|---|
| A | 90 et plus |
| B | 75 et plus |
| C | 60 et plus |
| D | 40 et plus |
| E | 20 et plus |
| F | moins de 20 |

## Codes de sortie

| Code | Signification |
|---|---|
| `0` | Scan terminé, aucun problème critique. |
| `1` | Scan terminé, au moins un problème critique. |
| `2` | Erreur : option ou domaine invalide, PDF impossible à générer, erreur imprévue ou interruption (Ctrl+C). |
| `3` | Refus : mode actif ou agressif sans `--jai-l-autorisation`. |

Exemple en intégration continue : `pmescan scan monsite.sn --json > rapport.json || echo "à traiter"`.

## Vie privée

L'analyse et le rapport restent sur votre machine. pmescan n'envoie de données à un
tiers que dans un seul cas :

- `--verifier-cve` interroge l'API publique `api.osv.dev`. Il lui envoie le **nom et la
  version du CMS détecté**, jamais le domaine analysé. Cette option est désactivée par
  défaut.

Bien sûr, le scan lui-même contacte le site analysé, ainsi que les serveurs DNS
configurés sur votre machine.

## Limites connues

- La table des branches de CMS maintenues est tenue à la main et en « meilleur effort ».
  Elle doit être revue régulièrement (`pmescan/checks/cms.py`).
- La base OSV couvre mal les cœurs de CMS : WordPress n'y figure pas. Une absence de
  faille signalée n'est donc pas une preuve d'absence de faille.
- La détection de DKIM ne teste que des sélecteurs courants. Un « DKIM non vérifiable »
  n'est donc pas une absence avérée, et il ne retire aucun point.
- pmescan repère des failles courantes. Il ne remplace pas un audit de sécurité complet.

## Avertissement légal

pmescan est un outil **défensif**. Le mode passif ne lit que des informations publiques.
Les modes actif et agressif sollicitent la cible et ne doivent être utilisés qu'avec
autorisation. Un usage non autorisé peut tomber sous le coup de la loi sénégalaise
n° 2008-11 sur la cybercriminalité, ou de ses équivalents ailleurs (art. 323-1 du Code
pénal français, CFAA aux États-Unis).

N'utilisez `--jai-l-autorisation` que si vous êtes propriétaire de la cible, ou si vous
détenez une **autorisation écrite** de son propriétaire (mandat d'audit, contrat ou e-mail
explicite) couvrant la période et le périmètre de l'analyse. Une autorisation verbale ne
suffit pas : conservez la preuve écrite. En passant ce flag, vous déclarez remplir ces
conditions.

Ce logiciel est fourni « tel quel », sans garantie. **La responsabilité de disposer des
autorisations nécessaires incombe entièrement à l'utilisateur.**

## Contribuer

Les contributions sont bienvenues, y compris non techniques : améliorer les explications
dans `pmescan/i18n/fr.yaml`, traduire en wolof. Voir **[CONTRIBUTING.md](CONTRIBUTING.md)**.

## Licence

MIT. Voir [LICENSE](LICENSE).
