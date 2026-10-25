# Modes actif et agressif — pmescan

> ⚠️ **À lire entièrement avant toute utilisation.** Les modes actif et agressif
> sollicitent activement la cible. Ils sont réservés aux analyses que vous êtes
> légalement autorisé à mener.

## 1. Les trois modes

| Mode | Commande | Ce qu'il fait | Autorisation |
|---|---|---|---|
| **Passif** | `--mode passif` *(défaut)* | Lit seulement ce que le site publie : certificat TLS, en-têtes HTTP, enregistrements DNS (SPF, DMARC, DKIM, MX, DNSSEC), page d'accueil pour reconnaître le CMS. | Non |
| **Actif** | `--mode actif --jai-l-autorisation` | Ajoute des requêtes vers des chemins sensibles, des fichiers de version du CMS et un test de ports TCP. | **Oui** |
| **Agressif** | `--mode agressif --jai-l-autorisation` | Réservé à de futures vérifications plus intrusives. **Dans la version 0.1, il fait exactement la même chose que le mode actif.** | **Oui** |

Le mode passif est le mode par défaut. Les deux autres ne se lancent jamais sans le flag
`--jai-l-autorisation`.

## 2. Ce que le mode actif envoie à la cible

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
- **Ports TCP** : une tentative de connexion sur 30 ports connus (bases de données,
  accès distant, administration). Aucune donnée n'est envoyée après l'ouverture : la
  connexion est fermée tout de suite.

Garde-fous intégrés :

- au plus **20 connexions simultanées** ;
- **2 secondes** maximum par tentative ;
- **une seule tentative** par port ;
- aucune tentative de mot de passe, aucun envoi de formulaire, aucune exploitation de
  faille.

Le scan reste léger, mais il laisse des traces : la cible peut voir ces requêtes dans
ses journaux, et un pare-feu peut bloquer votre adresse IP.

## 3. Cadre légal — obligatoire

Les modes actif et agressif ne se contentent plus de lire : ils **sollicitent
activement** un système informatique. Sans l'accord du propriétaire, cela peut
constituer une infraction :

- 🇸🇳 **Sénégal** : loi n° 2008-11 sur la cybercriminalité (accès et maintien frauduleux
  dans un système de traitement automatisé de données) ;
- 🇫🇷 **France** : articles 323-1 et suivants du Code pénal ;
- 🇺🇸 **États-Unis** : Computer Fraud and Abuse Act (CFAA).

**N'utilisez `--jai-l-autorisation` que si l'une de ces conditions est remplie :**

1. vous êtes propriétaire de la cible ;
2. vous détenez une **autorisation écrite** du propriétaire (mandat d'audit, contrat ou
   e-mail explicite) qui couvre la période et le périmètre de l'analyse.

Une autorisation verbale ne suffit pas. Conservez la preuve écrite.

## 4. Utilisation

```bash
pmescan scan exemple.sn --mode actif --jai-l-autorisation
```

Sans le flag, la commande refuse de s'exécuter **avant toute requête réseau** et se
termine avec le code de sortie `3` :

```
$ pmescan scan exemple.sn --mode actif
Refus : le mode actif sollicite activement la cible (exemple.sn). N'utilisez ce mode que sur une cible dont vous êtes propriétaire ou pour laquelle vous disposez d'une autorisation écrite de son propriétaire. Si c'est le cas, relancez la commande avec --jai-l-autorisation. Voir README-mode-agressif.md. Aucune requête n'a été envoyée.
```

Le flag ne sert qu'aux modes actif et agressif : il est ignoré en mode passif.

### Journal de consentement

Chaque scan actif ou agressif autorisé ajoute une ligne au fichier
`~/.pmescan/consent.log`, **avant** le début du scan. Chaque ligne contient trois champs
séparés par des tabulations : l'horodatage UTC, le domaine et le mode.

```
2026-10-25T15:18:33+00:00	exemple.sn	actif
```

Ce journal reste sur votre machine : il n'est envoyé nulle part. Pour le déplacer, réglez
la variable d'environnement `PMESCAN_DOSSIER`. Si le fichier ne peut pas être écrit,
pmescan affiche un avertissement et poursuit le scan.

## 5. Responsabilité

Ce logiciel est fourni « tel quel », sans garantie. Les auteurs et contributeurs ne
peuvent être tenus responsables d'un usage illégal ou dommageable. **La responsabilité
de disposer des autorisations nécessaires incombe entièrement à l'utilisateur.**

En passant le flag `--jai-l-autorisation`, vous déclarez remplir ces conditions.
