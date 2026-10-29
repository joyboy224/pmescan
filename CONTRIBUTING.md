# Contribuer à pmescan

Merci de votre intérêt ! Toutes les contributions comptent, même sans écrire de code :
- une explication plus claire dans `fr.yaml` ;
- une traduction ;
- un faux positif signalé ;
- une version de CMS à mettre à jour.

## Installer l'environnement de développement

```bash
git clone https://github.com/joyboy224/pmescan.git
cd pmescan
python -m venv .venv
.venv/bin/pip install -e ".[dev]"     # Windows : .venv\Scripts\pip install -e ".[dev]"
```

## Avant chaque proposition (pull request)

Les trois commandes suivantes doivent passer sans erreur :

```bash
python -m pytest -q
python -m ruff check pmescan tests
python -m mypy pmescan
```

Sous Windows, remplacez `python` par `.venv\Scripts\python.exe`.

Un test est ignoré si WeasyPrint ou ses bibliothèques système (Pango, GTK) sont absents.
C'est normal.

## Règles du projet

1. **Tout en français.**
   - Les noms de variables, de fonctions et de classes, les commentaires et les messages
     de commit sont en français.
   - Seuls les noms imposés par une bibliothèque restent en anglais (`status_code`,
     `wait_closed`, …).
2. **Aucun texte destiné à l'utilisateur dans le code.**
   - Un check produit un `Resultat` qui porte un `identifiant` stable, par exemple
     `dmarc_absent`.
   - L'explication en français se trouve dans `pmescan/i18n/fr.yaml`. Chaque entrée a
     cinq clés : `titre`, `risque`, `qui_corrige` (`hebergeur`, `developpeur` ou
     `gerant`), `effort` et `action`.
3. **Écrire pour un gérant, pas pour un expert.**
   - Le champ `risque` explique la conséquence concrète, sans jargon : par exemple
     « essais de mots de passe en masse » plutôt que « force brute ».
   - Le texte n'exagère pas : on écrit « peut permettre » plutôt que « permet ».
4. **Tests 100 % hors ligne.** Aucun test ne doit toucher le réseau :
   - les appels HTTP passent par `respx` ;
   - le DNS est simulé (`dns.asyncresolver.resolve`, `VerificationPorts._resoudre`) ;
   - sslyze est remplacé par les faux objets de `tests/conftest.py` ;
   - les connexions TCP passent par `faux_open_connection`.
5. **Aucune exception ne doit faire planter le scan.**
   - Un check gère lui-même ses erreurs réseau.
   - L'orchestrateur (`scanner.py`) sert de filet de sécurité : il transforme une
     exception imprévue en `<check>_erreur_interne`.
6. **Respecter les modes.**
   - Toute requête qui va au-delà de la simple lecture de ce que le site publie est
     réservée au mode `actif` : chemins sensibles, fichiers de version, connexions TCP.
   - Le mode `passif` ne doit jamais faire ce type de requête.
   - Une requête intrusive exige **aussi** `cible.autorisation`. `scanner()` ignore les
     vérifications de niveau actif quand `Cible.autorisation` vaut False. C'est la
     valeur par défaut, y compris lorsqu'on appelle pmescan depuis Python.
   - Une nouvelle sonde intrusive placée dans un check passif doit tester
     `cible.autorisation` elle-même, comme le fait `cms.py`.
7. **Pas de faux positif.**
   - Dans le doute, un check ne signale rien, ou signale en `INFO`, ce qui ne retire
     aucun point.
   - Un problème signalé à tort coûte la confiance du gérant.

## Ajouter une vérification

1. Créez `pmescan/checks/<nom>.py`, avec une classe qui hérite de `Verification` et
   déclare `nom`, `niveau_minimum` (`"passif"` ou `"actif"`) et `async def executer(self, cible)`.
2. Ajoutez-la à `VERIFICATIONS` dans `pmescan/scanner.py`.
3. Ajoutez une entrée dans `fr.yaml` pour **chaque** identifiant non réussi.
4. Écrivez `tests/test_<nom>.py`, qui couvre le cas « problème », le cas « tout va
   bien » et les erreurs réseau.
5. Ajoutez un scénario « problème » dans `_SCENARIOS_PAR_NOM` de `tests/test_i18n.py`.
   C'est obligatoire : sans ce scénario, le test échoue. Ce garde-fou assure que tout
   identifiant émis a bien son texte en français.

## Ajouter une langue

Copiez `pmescan/i18n/fr.yaml` en `<code>.yaml` (par exemple `wo.yaml` pour le wolof) et
traduisez les valeurs. Les **clés** ne changent pas. Une relecture par une personne de
langue maternelle est très appréciée.

## Mettre à jour les versions de CMS

La table `BRANCHES_MAINTENUES` de `pmescan/checks/cms.py` est tenue à la main. Pour la
corriger :
- indiquez dans la pull request la source officielle (calendrier de support du CMS) ;
- mettez à jour la date du commentaire.

## Signaler une faille de sécurité dans pmescan

Ne publiez pas les détails dans une issue publique. Utilisez le signalement privé de
vulnérabilité de la plateforme qui héberge le dépôt, ou ouvrez une issue qui demande
seulement un canal de contact privé.

## Éthique

pmescan est un outil défensif. Une contribution qui ajoute une capacité offensive
(exploitation de faille, essais de mots de passe, contournement de protections) ou qui
affaiblit la garde d'autorisation des modes intrusifs sera refusée.
