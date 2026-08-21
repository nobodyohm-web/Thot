# Thot

Un assistant de code en terminal qui **connaît déjà ton dépôt** — et le dépôt
où vivent **Hermes Agent** et **Prime Agent**, entiers.

Un agent conversationnel découvre un projet en ouvrant des fichiers avec le
modèle : lent, partiel, à repayer à chaque session. Thot calcule la même image
par AST et graphe d'appels — complète, instantanée, gratuite — et ne donne au
modèle que ce qui compte.

## Les trois programmes

Ce dépôt en contient trois, pas un. Aucun n'est une réécriture d'un autre :
chacun est là dans sa langue, avec son outillage, et Thot les branche
ensemble.

| | Ce qu'il est | Où |
|---|---|---|
| **thot** | audit déterministe, carte du code, mémoire des verdicts | `src/thot/` |
| **hermes** | l'agent : outils, passerelles, plugins, cron, ACP | `hermes/` — Python, membre du workspace uv |
| **prime** | l'agent de code : fournisseurs de modèles, TUI, RLM | `prime/` — TypeScript, npm |

```bash
thot                 # la session d'audit
thot hermes          # Hermes, arguments transmis tels quels
thot prime           # Prime, pareil
thot fusion status   # ce qui est présent, prêt, et branché
```

Le branchement n'est pas décoratif. `thot fusion wire` déclare le serveur MCP
de Thot dans les deux agents : ils gagnent `code_map`, `find_symbol`,
`callers`, `audit`, `skills` et `skill` — la carte complète du dépôt, calculée
hors modèle, au lieu de la redécouvrir fichier par fichier. C'est le renfort
mutuel : Thot sait sans demander, Hermes et Prime agissent.

Chaque agent garde sa configuration. `thot fusion unwire` défait tout, et le
`settings.json` de Prime est sauvegardé avant la première modification.

`thot fusion status` mesure ce qui **fonctionne**, pas ce qui est écrit :
Hermes installe les plugins portables désactivés, par sécurité, donc écrire
les deux fichiers ne branche rien tant que `plugins.enabled` ne le nomme pas.
L'activation passe par le CLI de Hermes, jamais par une édition de son
`config.yaml` — ce fichier est le sien, avec son schéma et ses migrations.

Ce qui n'est **pas** fusionné, et le reste sciemment : les trois gardent leur
configuration séparée (`~/.thot`, `~/.hermes`, `~/.prime`), leurs bibliothèques de
méthodes et leurs mémoires. Hermes et Prime ne sont pas encore des moteurs
pour `thot audit --deep`, qui passe toujours par le CLI Claude.

## Installation

```bash
uv tool install --editable --from /Users/dev/Desktop/Thot thot
```

Un seul `uv sync` à la racine installe Thot **et** Hermes : c'est un workspace,
pas une copie qui dérive. Prime est en TypeScript et se construit à part :

```bash
cd prime && npm install && npm run build
```

Sans Node, Thot et Hermes fonctionnent ; `thot fusion status` dit ce qui
manque et comment le réparer, plutôt que d'échouer au premier appel.

## Utilisation

```bash
thot
```

C'est tout. Au premier lancement il demande quel modèle connecter, puis il
scanne le dossier courant et te rend la main.

```
   ╔╦╗╦ ╦╔═╗╔╦╗
    ║ ╠═╣║ ║ ║    claude-opus-5
    ╩ ╩ ╩╚═╝ ╩

   ▪ dossier  ~/Desktop/Quanta
   ▪ code     142 python · 8 points d'entrée
   ▪ git      main · propre
   ▪ audit    1 high · 2 medium

   Reconnaissance en 0.31 s. Prêt.

   ›
```

Dossier vide, il le dit et attend tes instructions. Dossier avec du code, il
l'a déjà cartographié avant ta première phrase.

### Commandes de session

| Commande | Effet |
|---|---|
| `/audit` · `/audit deep` | relancer l'analyse, ou la faire réfuter par le modèle |
| `/verdict n refute …` | écarter un finding, avec sa raison |
| `/goal <objectif> --budget N` | fixer un objectif suivi entre les sessions |
| `/sessions` · `/resume` | ce qui a été fait ici avant, et y retourner |
| `/search <mots>` | chercher dans tout ce que Thot a dit ou trouvé |
| `/compact` | résumer et repartir avec un contexte vide |
| `/export` · `/import` | emporter une session ailleurs |
| `/skills` · `/plugins` · `/mcp` | ce qui est chargé, et le catalogue |
| `/scan` | recalculer la carte du dépôt |
| `/model` · `/clear` · `/quit` | modèle, oubli, sortie |

Plus les tiennes : tout fichier `.thot/commands/<nom>.md` devient `/<nom>`.

### Modèles

| Choix | Ce qu'il faut |
|---|---|
| **Claude — ton compte** | le CLI `claude` installé et connecté. Rien à copier. |
| **Claude — clé API** | une clé `sk-ant-…` |
| **OpenAI** | une clé API, ou `OPENAI_API_KEY` dans l'environnement |
| **Local** | Ollama ou LM Studio qui tourne — gratuit, hors ligne |
| **Autre** | n'importe quel endpoint compatible OpenAI |

`thot login` pour changer, `thot logout` pour oublier. La configuration vit dans
`~/.thot/config.json`, en `0600`. Aucun jeton n'y est stocké en mode compte.

#### Comment le mode compte fonctionne

L'API Messages refuse les jetons d'abonnement venant d'un programme tiers. Y
passer demanderait de se faire passer pour Claude Code — user-agent maquillé,
prompt système emprunté. Thot ne le fait pas.

Il fait l'inverse : il **délègue au client officiel**. Chaque tour lance

```
claude -p --output-format stream-json --session-id <uuid> \
       --mcp-config <outils Thot> --append-system-prompt <carte du dépôt>
```

L'inférence est faite par `claude`, sous ton compte, exactement comme si tu
l'avais tapé toi-même. Thot fournit la carte du dépôt, branche ses outils
déterministes via un petit serveur MCP, et met en forme le flux d'événements.
Le fil de conversation est porté par `--resume` sur le même identifiant de
session.

## Sessions — rien ne se perd

Ferme la fenêtre, l'audit et le raisonnement qui allait avec sont toujours là.
Chaque tour est écrit au moment où il arrive, dans `~/.thot/sessions.db`.

```
   › /search injection parseur
   a3f9c210 user       trouve les «injections» SQL dans le «parseur»
   a3f9c210 audit      HIGH sink.sqlite.execute  src/parse.py:88
   7b02e4d1 verdict    sink.os.system src/deploy.py:12 → refuted : commande littérale
```

La recherche couvre ce qui a été **dit** et ce qui a été **trouvé** : un
finding à moitié retenu se retrouve avec les mots dont on se souvient.

```bash
thot sessions              # ce qui a été fait dans ce dépôt
thot sessions --all        # partout
thot sessions --show <id>  # la transcription entière
thot search <mots>         # sans ouvrir de session
thot export <id> --out s.json ; thot import s.json
```

`/resume` rend la transcription **et** le contexte : en mode compte, Thot a
gardé l'identifiant de conversation du CLI officiel et le lui rend, donc le
modèle se souvient au lieu de relire.

`/compact` clôt la session sur un résumé et continue dans une session enfant
qui garde le lien. Compacter coûte du contexte, jamais des preuves : la session
parente reste entière et `/search` la trouve toujours.

## Objectifs — savoir quand s'arrêter

Un objectif survit à la conversation qu'il traverse, et se rappelle au modèle
à chaque tour, y compris juste après un `/compact`.

```
   › /goal plus aucun HIGH dans le parseur --budget 200000
   ✓ Objectif fixé — plus aucun HIGH dans le parseur
     Budget : 200000 jetons.
```

Épuiser le budget est un **état**, pas une erreur : Thot ne s'arrête pas au
milieu d'un tour, il finit, passe en `budget_limited` et dit où en est
l'objectif. À toi de choisir entre `/goal budget 500000` et `/goal done`.

## Mémoire — décider une fois

Le coûteux dans un audit n'est pas de trouver des candidats : les phases
déterministes le font en quelques secondes, gratuitement. C'est de **décider
ce qu'ils valent**. Perdre ces décisions entre deux runs, c'est ce qui rend un
outil de sécurité insupportable — les mêmes quarante rejets, chaque semaine,
jusqu'à ce que plus personne ne lise le rapport.

```
   › /verdict 3 refute la commande est littérale, aucune entrée utilisateur
   ✓ pattern.os_system_injection à app/shellutil.py:5 — refuted
   Retenu tant que ce code ne change pas.
```

| Décision | Effet |
|---|---|
| `refute` | faux positif — passe en INFO, sort du rapport, garde sa raison |
| `accept` | risque réel, assumé — passe en INFO, annoté |
| `fixed` | corrigé — s'il **revient**, c'est signalé comme régression |

### Pourquoi c'est sûr

Un verdict est indexé sur `Finding.compute_id`, qui hache la règle, le fichier,
le symbole et **l'AST normalisé** de ce symbole. Reformate, déplace la
fonction, renomme une variable locale : le verdict tient. Change ce que le code
*fait* : l'identifiant change avec lui, et **le verdict expire tout seul**.

Un rejet ne peut donc jamais survivre au code qu'il concernait. C'est la seule
propriété qui rend le fait de mémoriser des rejets acceptable.

L'identifiant nomme aussi **l'appel exact** visé — `httpx.get#3` — et pas
seulement la fonction qui le contient. Sans cela, cinq appels réseau dans la
même fonction ne faisaient qu'un seul finding aux yeux de la mémoire, et
écarter le premier écartait les quatre autres avec leur raison. Ce
discriminant ne fragilise rien : il n'a besoin d'être unique que dans une
version du corps, et l'AST de ce corps fait déjà expirer tout ce qui s'y
rapporte dès qu'il bouge.

```bash
thot verdicts                    # tout ce qui a été décidé
thot verdicts --path src/auth    # sur un chemin
thot verdicts --forget <id>      # revenir sur une décision
thot audit . --no-memory         # ignorer la mémoire pour ce run
```

Une décision survit au finding qui l'a produite : le code change, le finding
prend une nouvelle identité, et l'ancienne décision ne désigne plus rien. La
liste marque celles-là `[absent du dernier audit]` plutôt que de les afficher
comme les autres — six décisions dont trois sont mortes ne doivent pas se lire
comme six décisions vivantes.

La mémoire s'applique **avant** le modèle : un finding qui porte déjà une
décision — écarté, accepté ou corrigé — n'est jamais renvoyé à l'analyse. Un
run où tout est décidé ne fait aucun appel. Ce n'est pas qu'une économie : la
sonde remplace la confiance, la sévérité, le scénario et la provenance d'un
coup, donc renvoyer une décision au modèle l'écraserait, et effacerait qui
l'avait prise. Une régression est le cas où cela compte le plus : elle a déjà
été jugée réelle une fois, aucune passe profonde ne peut la faire taire.

Et les réfutations s'enregistrent d'elles-mêmes, depuis `thot audit --deep`
comme depuis `/audit deep` : deux appels modèle, payés une fois. Elles portent
le nom du moteur qui a décidé, jamais le tien — une décision machine ne prend
pas le pas sur une décision humaine.

Rien n'est jamais supprimé en silence. Un finding écarté reste dans le rapport
en `refuted`, avec sa raison et son auteur — un audit qui cache ce qu'on lui a
dit d'ignorer n'est pas relisable.

## Le noyau Python

L'idée maîtresse de Prime Agent, portée : plutôt qu'un appel d'outil par
question, le modèle écrit du Python et **ses variables survivent**.

```
   › /py bas = audit(severity="low"); print(len(bas), "findings"); [f.rule for f in bas]
   3 findings
   → ['sink.eval', 'sink.network', 'sink.subprocess.shell']

   › /py len(files())
   → 148
```

La carte du dépôt y est disponible comme objets — `files()`, `symbols()`,
`find()`, `callers()`, `callees()`, `audit()`, `read()`. Une boucle qui croise
findings et appelants coûte **un** tour de modèle ; la même chose en appels
d'outils en coûte une douzaine, dont chacun repaie la lecture de ce que la
carte savait déjà.

**Le noyau ne tourne jamais dans le processus de Thot.** Un `exec()` chez soi
donnerait au code audité la mémoire de Thot, ses bases ouvertes et ses
descripteurs de fichiers. C'est donc un sous-processus — et *dans le conteneur*
quand un bac à sable est configuré.

Ce que ça protège, exactement — et Thot l'a corrigé sur lui-même après que sa
propre passe adverse a pointé une docstring trop absolue :

| | |
|---|---|
| Sous-processus (`local`) | protège la mémoire, les bases et les descripteurs de Thot. **Pas** tes identifiants : le worker tourne sous ton compte et peut lire `~/.claude/.credentials.json`. |
| Conteneur (`docker`) | frontière réelle : pas de réseau, pas ton `$HOME`, dépôt en lecture seule. |

Les variables d'environnement sensibles sont retirées avant le lancement, et
`/py` le dit une fois en mode local plutôt que de laisser « processus séparé »
se lire comme une garantie qu'il n'offre pas.

### `rlm()` — déléguer depuis une cellule

```python
verdicts = {f.id: rlm(f"Ce chemin est-il exploitable ?\n{f.failure_scenario}")
            for f in audit(severity="high")}
```

Une cellule peut décomposer son propre problème. La cellule ne détient aucun
identifiant : elle **demande** à l'hôte, qui décide et paie. Les limites sont
donc tenues côté hôte — 8 appels par cellule, 40 par noyau — parce qu'une
limite que l'enfant pourrait modifier n'est pas une limite, et l'enfant exécute
du code venu du dépôt audité.

### Ce que Thot retient d'un dépôt

```
   › /harness note team.shell.run : échappe ses arguments, les findings dessus sont faux
   ✓ Retenu — rappelé à chaque session.
```

Le raffinement de Prime, appliqué à l'audit : des faits qu'aucune analyse
statique ne dérivera jamais. Ils vivent dans `<dépôt>/.thot/harness.json`,
relus en pull request comme les verdicts, et reviennent dans le briefing à
chaque session.

## Ce que le modèle a le droit de faire

```bash
thot --tools lecture      # lire et raisonner, jamais modifier
thot --tools carte        # la carte seule : aucun fichier ouvert
```

En session : `/tools lecture`. Relire un dépôt qui n'est pas le tien, c'est
lire du code dont tu as toute raison de te méfier — et que le modèle le
modifie est rarement ce que tu voulais.

La posture tient à **trois** endroits, pas un : les outils proposés au modèle,
le moment où il en appelle un quand même, et — en mode compte — le CLI
officiel, à qui `--disallowed-tools` interdit `Write`, `Edit` et `Bash`. Une
posture qui ne filtrerait que les outils de Thot serait un mensonge là où ça
compte le plus.

## La chaîne d'approvisionnement

```bash
thot deps                       # les dépendances épinglées, contre OSV.dev
thot deps --list                # ce qui a été trouvé, sans réseau
thot deps --fail-on high        # code 1 en CI
thot audit . --deps             # dans le rapport d'audit
thot mcp check                  # tes serveurs MCP sont-ils malveillants ?
```

Les verrous d'abord, toujours : `uv.lock`, `poetry.lock`, `Pipfile.lock`,
`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`. Un manifeste dit
`requests>=2` et OSV ne sait pas répondre à un intervalle ; un verrou dit
`2.31.0` et OSV sait. **Une dépendance qui n'existe qu'en intervalle n'est pas
devinée**, elle est rapportée comme non épinglée.

Un avis qui couvre une version exacte est un fait, pas une supposition — mais
savoir si *ton* code atteint la fonction vulnérable n'est pas analysé, alors
ces findings restent `PLAUSIBLE` et le disent. Seul `MAL-*` fait exception :
le paquet **est** la charge utile, l'atteignabilité n'est pas la question.

Et la même propriété que partout ailleurs : l'identité d'un finding porte la
version épinglée, donc **un `bump` fait expirer le verdict**. Écarter une CVE
sur `requests==2.19.1` n'écarte rien sur `2.20.0`.

OSV injoignable ne devient jamais un certificat de bonne santé : `thot deps`
dit « non vérifiées » et rend un code d'erreur.

## Exécuter le code audité sans l'exécuter chez toi

`pytest` sur un dépôt audité, c'est le code de ce dépôt qui tourne sous ton
compte. C'est le seul endroit où toute la conception fuit.

```bash
thot sandbox status
thot sandbox use docker
thot sandbox show pytest -q     # la commande docker exacte, à relire
```

Par défaut, dans le conteneur :

| | |
|---|---|
| Réseau | **coupé** (`--network none`) |
| Dépôt | monté en lecture seule, copie inscriptible en tmpfs |
| Privilèges | `--cap-drop ALL`, `no-new-privileges`, utilisateur 65534 |
| Bornes | `--pids-limit`, `--memory`, `--cpus`, `--rm` |

Le réseau coupé est le drapeau qui vaut le plus et celui qui gêne le plus :
c'est pourquoi c'est un drapeau et pas une loi (`--network`).

**Une règle inverse celle du reste de Thot** : partout ailleurs, une
dépendance manquante coûte sa fonctionnalité et le travail continue. Ici, un
bac à sable demandé et indisponible **refuse d'exécuter**. Retomber
silencieusement sur l'hôte transformerait une protection en mensonge.

## Partager les décisions

Un verdict est un fait sur *cette révision de ce code*. Il voyage donc avec
le code : `<dépôt>/.thot/verdicts.json`, relu dans la pull request qui touche
le code concerné, et présent dans un clone neuf avant même le réseau.

```bash
thot verdicts --share <id>   # publier une décision locale dans le dépôt
thot verdicts --where        # d'où viennent les décisions, où elles s'écrivent
```

La chaîne par défaut, sans aucune configuration : **le dépôt d'abord, ta
machine ensuite**. Une décision passée en revue prime sur une note que tu
t'es faite à toi-même.

L'écriture, elle, reste locale. Un outil qui modifierait un fichier versionné
à chaque `/verdict` produirait des diffs que personne n'a demandés : tu décides
en local, tu publies exprès.

### Un serveur partagé, ou un mem0 existant

```json
// ~/.thot/memory.json
{"remote": {"kind": "http", "base_url": "https://audit.equipe.example", "token": "…"}}
{"remote": {"kind": "mem0", "host": "http://localhost:8888", "api_key": "…"}}
```

Le backend `mem0` parle le contrat auto-hébergé exactement comme le client
d'Hermes Agent : un serveur déjà en place pour Hermes sert Thot sans rien
changer.

Un magasin distant injoignable coûte la mémoire des décisions passées, jamais
l'audit — mais il ne le fait pas en silence : `thot verdicts --where` dit
lequel est muet et pourquoi.

## Recevoir les audits ailleurs

Un audit qui se termine à 03:00 ne vaut rien tant que personne n'est prévenu,
et la personne à prévenir n'est pas devant le terminal.

```bash
thot gateway add ntfy topic=thot-topic
thot gateway add telegram token=… chat_id=…
thot gateway allow telegram <ton-id>     # obligatoire pour commander
thot gateway test
thot serve                                # écouter les commandes
```

| Canal | Sortant | Entrant |
|---|---|---|
| Telegram | ✓ | ✓ (long polling — aucun port à ouvrir) |
| Discord · Slack | ✓ (webhook) | — |
| ntfy | ✓ | — (pas d'identité : le sujet suffit à publier) |
| Courriel | ✓ (SMTP) | — |

Les notifications ne demandent aucun démon : le plugin `gateway-notify` se
déclenche sur `post_audit`, et **seulement** pour un audit non surveillé.
Un audit lancé à la main s'affiche déjà à l'écran ; notifier à chaque fois
apprend au destinataire à couper le canal, ce qui coûte le seul message qui
comptait. Rien de neuf : silence.

### Ce qu'un jeton volé permet

Le démon n'existe que pour le retour, et sa conception tient surtout à ça :

- **le jeu de commandes est fermé** — `status`, `audit`, `findings`, `verdict`,
  `help`. Pas de shell, pas d'écriture, pas de chemin arbitraire ;
- **un audit ne peut viser qu'un dépôt déjà déclaré** par `thot schedule add` ;
- **l'entrant exige une liste d'autorisation**. Hermes propose un
  `ALLOW_ALL_USERS` pour le développement ; Thot n'a pas d'équivalent. Sans
  liste, le canal est sortant seulement, et `thot serve` le dit.

`~/.thot/gateway.json` est écrit en `0600` — il contient des jetons de bot et
un mot de passe SMTP. Les variables d'environnement le surchargent champ par
champ, sous les noms d'Hermes.

## Audits programmés

```bash
thot schedule add nuit ~/mon-projet --every daily --threshold high
thot schedule list
thot schedule run nuit            # ce que le planificateur appelle
thot schedule remove nuit
```

Thot écrit l'unité `launchd` (macOS) ou te donne la ligne de crontab, et te
laisse l'activer toi-même — un outil qui installe des tâches de fond en
silence est un outil qu'on cesse de croire.

**Un audit programmé ne dit rien tant que rien n'est nouveau.** Un rapport
nocturne qui répète les mêmes trois cents findings finit dans un dossier que
personne n'ouvre. Ce qui remonte, c'est le diff : ce qui est apparu depuis la
dernière fois, au-dessus du seuil, moins ce qui a déjà été jugé sans intérêt.

## Plugins

Cinq hooks, chacun parce que quelque chose de livré s'en sert :

| Hook | Quand |
|---|---|
| `on_finding` | avant le rapport, pour annoter |
| `post_audit` | audit terminé — notifier, exporter, archiver |
| `pre_write` | avant une écriture de l'agent — renvoie un avertissement |
| `post_write` | après une écriture réussie |
| `on_verdict` | une décision vient d'être enregistrée |

Un plugin est un dossier avec `plugin.yaml` et `__init__.py`, dans
`~/.thot/plugins/` ou `<repo>/.thot/plugins/` — la forme utilisée par Hermes
Agent. Un plugin qui plante coûte sa propre fonctionnalité et rien d'autre :
son erreur est enregistrée et affichée par `/plugins`.

Trois sont livrés :

| Plugin | Ce qu'il fait |
|---|---|
| `write-guard` | relit ce que le modèle écrit et fait remonter un avertissement si un motif dangereux apparaît. Non bloquant — un faux positif qui bloque une session est pire que l'écriture. |
| `regression-alert` | un défaut marqué `fixed` qui réapparaît passe en CRITICAL : une régression vaut plus qu'un candidat neuf. |
| `audit-log` | un journal JSONL local de chaque audit, verdict et écriture, dans `~/.thot/journal.jsonl`. Aucun réseau. |

## Skills — les méthodes que Thot connaît

Une skill est une méthode écrite une fois : un `SKILL.md` avec un frontmatter
YAML. C'est **le format de Hermes Agent et de Prime Agent**, donc une skill
écrite pour l'un des deux se charge ici sans modification, et l'inverse est
vrai.

Thot embarque **la bibliothèque complète d'Hermes Agent** (MIT — voir
`NOTICE.md`) : 90 méthodes chargées, 117 de plus disponibles.

```bash
thot skills list              # les 90 chargées
thot skills search pentest    # y compris la bibliothèque optionnelle
thot skills install ast-grep  # activer une optionnelle
thot skills show plan         # ce que lirait le modèle
```

Catégories chargées : `audit`, `security`, `software-development`, `github`,
`devops`, `research`, `mlops`, `productivity`, `creative`, `apple`, `email`,
`media`, `note-taking`, `smart-home`, `social-media`,
`autonomous-ai-agents`.

Le modèle les découvre avec l'outil `skills` — qui répond par un **index de
noms** tant qu'on ne lui donne pas de mot-clé, parce que deux cents
descriptions ne sont pas un catalogue — et lit celle qui s'applique avec
`skill`. En session, `/skills` te montre la même chose.

Une méthode importée qui cite un outil absent ici (`delegate_task`,
`browser_navigate`…) est servie telle quelle, avec une note disant lesquels
manquent et quoi utiliser à la place. La démarche se transporte même quand
l'appel d'outil ne se transporte pas.

### En ajouter

```
~/.thot/skills/<nom>/SKILL.md            # partout où tu travailles
<repo>/.thot/skills/<nom>/SKILL.md       # versionné avec ce dépôt
```

```markdown
---
name: ma-méthode
description: Ce qu'elle fait et quand s'en servir.
---

# Ma méthode

Les étapes, dans l'ordre.
```

Les deux dispositions sont acceptées : un dossier plat (Prime Agent) ou groupé
par catégories (Hermes Agent). Un nom qui existe déjà remplace la version
embarquée — de quoi adapter une méthode livrée sans la forker.

### Une méthode fournie par le dépôt audité est analysée d'abord

Un `SKILL.md` est du texte remis au modèle **comme instruction**. Les dépôts
que Thot lit sont, par définition, ceux dont personne ne répond. Un dépôt
hostile qui dépose `.thot/skills/x/SKILL.md` écrirait une partie du briefing.

Le garde d'Hermes Agent est porté ici et passe sur tout ce qui vient du dépôt :
injection, exfiltration, persistance, obfuscation.

```
   ▲ 1 skill(s) fourni(s) par ce dépôt ont été refusés — ils seraient passés
     au modèle comme instructions.
     pwn   curl vers l'extérieur ; accès à ~/.thot ; « ignore previous
           instructions »
```

`thot skills scan <dossier>` pose la même question à la demande. Ce que Thot
livre lui-même n'est pas analysé : c'est sur disque parce que le programme est
installé, pas parce qu'un dépôt l'a demandé.

## Commandes personnalisées

Un fichier markdown est une commande. La grammaire est celle de Prime Agent,
Claude Code et Codex — rien de nouveau à apprendre.

```markdown
---
description: Relire un fichier sans rien modifier.
argument-hint: <chemin>
---

Relis $1 et dis-moi ce qui cloche. Ne modifie rien.
```

Dans `.thot/commands/revue.md`, cela crée `/revue src/app.py`. Substitutions :
`$1`, `$2`…, `$@`, `$ARGUMENTS`, `${@:2}`, `${@:2:3}`. Un argument n'est jamais
ré-interprété. Les commandes du dépôt passent par le même garde que ses skills.

Trois sont livrées : `/triage` (nommer l'entrée ou classer sans suite),
`/harden` (test qui échoue d'abord, correctif ensuite), `/regress` (l'audit
diffé contre une référence git).

## Serveurs MCP

Le catalogue d'Hermes Agent, vingt serveurs vérifiés :

```bash
thot mcp list            # le catalogue, et ce qui est déjà connecté
thot mcp show sentry
thot mcp add linear
```

L'installation est déléguée au CLI officiel, qui possède déjà OAuth et le
renouvellement de jetons — Thot n'a aucune raison de détenir un second coffre
à faire fuir. Il dit explicitement qu'*enregistré* n'est pas *autorisé*, et
quelle commande finit le travail.

## Les outils du modèle

Les classiques — lire, écrire, éditer, lancer une commande. Toute écriture et
toute exécution demandent confirmation, et ce n'est pas configurable.

Et quatre qui n'appartiennent qu'à Thot, **gratuits** parce qu'ils interrogent
la carte et non le modèle :

| Outil | Réponse |
|---|---|
| `code_map` | les fichiers du projet |
| `find_symbol` | fichier, lignes et paramètres d'une fonction |
| `callers` | qui appelle quoi, et la distance à un point d'entrée |
| `audit` | les chemins de teinte source → sink |

En mode compte, ces quatre-là sont servis au CLI officiel par
`thot.mcp_server` — un serveur MCP en lecture seule, incapable d'écrire ou
d'exécuter quoi que ce soit.

Quand le modèle cherche qui appelle `process_payment`, il interroge le graphe et
obtient la réponse complète — au lieu de grep trois fichiers au hasard.

## Mode audit seul

Le noyau d'analyse s'utilise aussi sans modèle, sans réseau, sans coût :

```bash
thot init /chemin/du/repo --owner "Ton Nom"   # autorisation, une fois
thot audit /chemin/du/repo --paths            # chemins de teinte complets
thot audit . --all                            # y compris le bruit faible
thot audit . --json --out rapport.json
thot audit . --fail-on high                   # code 1 en CI
```

### Analyse assistée — `--deep`

L'analyse déterministe répond à « ces données *pourraient*-elles circuler ? ».
C'est exhaustif, gratuit, et ce n'est pas la question qu'on paie un auditeur à
trancher. `--deep` pose la question chère, sur les seuls candidats qui l'ont
méritée :

```bash
thot audit . --deep                  # 20 pires candidats, 4 en parallèle
thot audit . --deep --budget 50      # plus large
thot audit . --deep --parallel 8     # plus vite
```

Deux passes, volontairement adverses :

1. **La sonde** doit nommer une entrée concrète qui atteint le point
   dangereux. Pas de généralité sur la classe de vulnérabilité — une URL, une
   valeur, un effet.
2. **La réfutation** reçoit ce scénario avec pour seule mission de le
   détruire : validation en amont, appelant qui ne passe que des constantes,
   type qui interdit l'entrée supposée. En cas de doute, elle réfute.

Un finding ne survit que si une seconde lecture hostile du même code échoue à
le tuer. `confirmed` veut alors dire quelque chose.

En session, la même chose : `/audit deep`.

Le moteur est choisi automatiquement — ton compte Claude via le CLI officiel
s'il est connecté (les analyses tournent en parallèle, sur ton abonnement),
une clé API sinon.

### Ce que l'audit ne doit pas lire

```
# .thotignore, à la racine du dépôt
vendor/
*.generated.py
tests/fixtures/
```

Les exclusions intégrées couvrent ce que tout dépôt a — `node_modules`,
`build`, `.venv`. `.thotignore` couvre ce que seul ce dépôt sait : de la
documentation embarquée, un client généré, un dossier de fixtures cassées
exprès. Les auditer ne produit pas des findings, ça produit du bruit à
l'endroit exact où seraient les findings.

### Tes propres règles

Le catalogue intégré connaît la bibliothèque standard. Il ne connaît pas le
wrapper que ton équipe a écrit autour de `subprocess`, la file que ton service
consomme, ni le validateur qui rend une valeur sûre chez toi. Sans un endroit
où le dire, chaque audit d'un vrai système se trompe aux trois mêmes endroits.

```yaml
# <repo>/.thot/rules/team.yaml   — versionné avec le code
# ~/.thot/rules/*.yaml           — ce que tu sais, partout où tu travailles
sinks:
  - id: sink.team.run_shell
    patterns: [run_shell, shellutil.run_shell]
    impact: critical
    description: Wrapper shell interne (shell=True)
    match_mode: bare          # qualified | method | bare | prefix

sources:
  - id: source.queue
    patterns: [msg.payload]
    description: File de messages
    match_mode: prefix        # couvre msg.payload.decode(...)

sanitizers: [validate_host, team.escape]
```

Une règle qui reprend un `id` intégré le **remplace** — de quoi dégrader un
sink que l'équipe a délibérément accepté, sans patcher Thot. Un fichier mal
formé arrête l'audit en nommant le fichier et la clé fautive, plutôt que de
laisser croire à une absence de finding.

### Calibration

La précision compte autant que la détection. Sont volontairement **non**
rapportés :

- `subprocess.run(cmd)` sans `shell=True` — aucun shell ne lit la commande.
- `cursor.execute("… ?", params)` — requête littérale, paramètres liés.
- Une valeur passée par `int()`, `shlex.quote()`, `os.path.basename()`,
  `html.escape()` — ces appels cassent la chaîne de contamination.
- Un défaut qu'aucun point d'entrée n'atteint est dégradé automatiquement —
  mais seulement si des points d'entrée ont été trouvés. Sans aucun, la
  portée est *inconnue*, pas *nulle*, et rien n'est enterré sur cette
  ignorance.
- `payload.get(...)` n'est pas `requests.get(...)`.

Ordre de grandeur, mesuré sur Hermes Agent (4 457 fichiers Python) : **98 s**,
365 findings dont 25 high — 3 au-dessus du seuil par défaut une fois la mémoire
appliquée.

### Ce que le graphe ne peut pas suivre

Un défaut atteint par un chemin que l'analyse ne résout pas — un handler rangé
dans une table de dispatch, une vue décorée, un appel sur une variable dont le
type est inconnu — n'est **pas** un défaut injoignable. Thot distingue les deux :

```python
HANDLERS = {"run": run_command}     # aucun appel : le graphe ne voit rien
@app.route("/ping")                 # enregistré à l'import par le décorateur
sandbox.run("pytest")               # plusieurs `run` répondent à ce nom
```

Dans les trois cas la portée est **inconnue**, pas nulle, et le finding garde
une pénalité légère au lieu d'être enterré. Sur Hermes : mêmes 365 findings,
mais **60 remontent d'un cran**. Une fonction que personne n'appelle *et* que
personne ne mentionne reste, elle, correctement décotée — sinon le filtre
cesserait d'être un filtre.

## Limites

Python uniquement pour l'analyse. Sans `--deep`, chaque finding est
`PLAUSIBLE` : détecté statiquement, pas encore prouvé par exécution. Avec
`--deep`, un finding `confirmed` a survécu à une réfutation adverse — ce
n'est pas encore une preuve d'exécution, qui viendra avec le repro. L'absence de finding n'est pas
une preuve d'absence de défaut — dispatch dynamique, réflexion et
métaprogrammation échappent à l'analyse.

## Développement

```bash
cd ~/Desktop/Thot
uv run pytest -q
```

Installé en éditable : le code source fait foi immédiatement. En revanche, si
`pyproject.toml` change (nouvelle dépendance), il faut relancer
`uv tool install --editable --from . thot --force`.

Le noyau déterministe (`codemap`, `taint`, `scope`, `scoring`, `store`,
`report`) ne dépend d'aucun agent et ne touche pas au réseau — un test le
vérifie et fait échouer la suite si ça change.

Spec et plans : `docs/superpowers/`.
