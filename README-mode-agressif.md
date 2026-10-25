# Mode agressif — pmescan

> ⚠️ **À lire entièrement avant toute utilisation.** Ce mode est réservé aux tests
> que vous êtes légalement autorisé à mener. Une mauvaise utilisation est illégale
> et peut endommager la cible.

## 1. Qu'est-ce que le mode agressif ?

`pmescan` propose trois niveaux d'analyse :

| Niveau | Flag | Ce qu'il fait | Autorisation requise |
|---|---|---|---|
| **Passif** | *(défaut)* | Lit seulement les informations publiées par le site (TLS, en-têtes HTTP, DNS, SPF/DMARC). N'envoie aucune requête intrusive. | Non |
| **Actif** | `--active` | Teste des ports critiques et quelques chemins sensibles (`/.git/`, `/.env`). | Oui |
| **Agressif** | `--aggressive` | Sollicite activement la cible : brute-force de chemins, énumération CMS complète, scan de tous les ports, fuzzing de paramètres, vérification active de vulnérabilités. | **Oui, écrite** |

Le mode agressif **n'est jamais activé par défaut**. Il nécessite un flag explicite et
une confirmation au lancement.

## 2. Ce que le mode agressif envoie à la cible

- Brute-force de répertoires et fichiers à partir d'un dictionnaire (génère beaucoup de 404).
- Énumération forcée des plugins et thèmes CMS, pas seulement ceux visibles.
- Scan complet des 65535 ports avec détection de version de service.
- Fuzzing des paramètres d'URL et des formulaires (détection XSS, erreurs SQL, traversée de chemin).
- Requêtes conçues pour confirmer qu'une CVE est réellement exploitable.

### Conséquences techniques

- **Charge serveur élevée.** Peut ralentir ou faire tomber un site hébergé en mutualisé.
- **Détection.** Des milliers de requêtes déclenchent les WAF/IDS et peuvent faire bannir votre IP.
- **Logs.** La cible verra son journal rempli d'alertes de sécurité.
- **Risque de données.** Le fuzzing de formulaires actifs peut créer des comptes, envoyer
  des messages ou corrompre des données.

N'utilisez jamais ce mode sur un environnement de production sensible sans fenêtre de
maintenance convenue avec le propriétaire.

## 3. Cadre légal — obligatoire

Le mode agressif n'est plus de la simple lecture : il **sollicite activement** un système
informatique. Sans autorisation du propriétaire, cela constitue une infraction.

- 🇸🇳 **Sénégal** : loi n° 2008-11 sur la cybercriminalité (accès et maintien frauduleux
  dans un système de traitement automatisé de données).
- 🇫🇷 **France** : articles 323-1 et suivants du Code pénal.
- 🇺🇸 **États-Unis** : Computer Fraud and Abuse Act (CFAA).

**Vous n'êtes autorisé à utiliser `--aggressive` que si l'une de ces conditions est remplie :**

1. Vous êtes propriétaire de la cible, **ou**
2. Vous détenez une **autorisation écrite** signée du propriétaire (mandat de test
   d'intrusion, contrat, ou e-mail explicite), couvrant la période et le périmètre du scan.

Une autorisation verbale ne suffit pas. Conservez la preuve écrite.

## 4. Utilisation

```bash
pmescan example.sn --aggressive --i-have-written-authorization
```

Sans le flag `--i-have-written-authorization`, la commande refuse de s'exécuter.

Au lancement, l'outil affiche un bandeau de consentement que vous devez confirmer :

```
================= MODE AGRESSIF =================
Cible        : example.sn
Date         : 2026-10-24 14:30
Ce scan va solliciter activement la cible.
Vous déclarez disposer d'une autorisation écrite
du propriétaire de ce système.

Taper "OUI J'AI L'AUTORISATION" pour continuer :
```

Cette confirmation, avec la cible et l'horodatage, est enregistrée localement dans
`~/.pmescan/consent.log` à des fins de traçabilité.

### Options de sécurité recommandées

```bash
# Limiter le débit pour ne pas saturer la cible (requêtes par seconde)
pmescan example.sn --aggressive --i-have-written-authorization --rate-limit 10

# Restreindre le périmètre à un sous-domaine précis
pmescan app.example.sn --aggressive --i-have-written-authorization --scope app.example.sn
```

## 5. Responsabilité

Ce logiciel est fourni « tel quel », sans garantie. Les auteurs et contributeurs ne
peuvent être tenus responsables d'un usage illégal ou dommageable. **La responsabilité
de disposer des autorisations nécessaires incombe entièrement à l'utilisateur.**

En utilisant le mode agressif, vous acceptez ces conditions.
