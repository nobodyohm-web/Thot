# Thot

[![tests](https://github.com/nobodyohm-web/Thot/actions/workflows/tests.yml/badge.svg)](https://github.com/nobodyohm-web/Thot/actions/workflows/tests.yml)
[![python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue)](pyproject.toml)
[![youden](https://img.shields.io/badge/Youden%20J-%2B55.5%25-brightgreen)](#le-thermomètre-et-la-boucle-qui-sen-sert)
[![false positives](https://img.shields.io/badge/faux%20positifs-0%20%2F%209%20150-brightgreen)](#le-thermomètre-et-la-boucle-qui-sen-sert)

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

Les deux agents ne s'atteignent pas de la même façon, et prétendre le
contraire ne branchait qu'un des deux. Hermes démarre le serveur lui-même et
lui parle sur le tuyau qu'il a ouvert. Prime n'accepte que du HTTP — son
`mcp-manager` jette toute entrée dont le type n'est pas `http`, et son
runtime n'a aucun transport sur tuyau — donc son côté demande un serveur qui
tourne :

```bash
thot fusion wire            # écrit les deux branchements, chacun dans sa forme
thot mcp serve --http       # ce que Prime interroge : boucle locale, jeton bearer
thot mcp service --install  # et pour que ce soit encore vrai demain
```

La troisième ligne existe parce que les deux premières ne tiennent qu'une
session. `fusion wire` écrit `http://127.0.0.1:8787/mcp` dans la
configuration de Prime, et cette adresse est vraie tant qu'un terminal reste
ouvert : au premier redémarrage, le fichier promet un serveur que plus
personne ne sert. `thot mcp service --install` écrit l'unité qui le relance —
`KeepAlive` sur macOS, `Restart=always` sous systemd — et **ne la charge
pas** : Thot imprime la commande et te laisse la lancer, parce qu'un outil
qui enregistre des agents en tâche de fond sans le dire est un outil qu'on
cesse de croire. `thot doctor` pose ensuite la seule question qui compte —
est-ce que l'adresse répond *maintenant* — et non pas si le fichier existe.

`fusion wire` installe aussi, chez Prime, le paquet de méthode que Thot livre
pour lui : une entrée de configuration ne suffit pas, Prime n'atteint un
serveur MCP qu'à travers une classe qui le nomme. Et il dépose le jeton dans
`auth.json` sans toucher aux identifiants du modèle — sans jeton, la
connexion échoue avant d'être ouverte.

Chaque agent garde sa configuration. `thot fusion unwire` défait tout, et le
`settings.json` de Prime est sauvegardé avant la première modification.

`thot fusion status` mesure ce qui **fonctionne**, pas ce qui est écrit :
Hermes installe les plugins portables désactivés, par sécurité, donc écrire
les deux fichiers ne branche rien tant que `plugins.enabled` ne le nomme pas.
L'activation passe par le CLI de Hermes, jamais par une édition de son
`config.yaml` — ce fichier est le sien, avec son schéma et ses migrations.
Il vérifie aussi que l'interpréteur qui lance Hermes sait importer le SDK
MCP, parce qu'un agent qui ne l'a pas n'a **aucun** outil — pas seulement pas
ceux de Thot — et le dit en `logger.debug`, où personne ne le lit. Enfin il
demande au serveur de Prime s'il répond : une adresse écrite dans un fichier
n'est pas une connexion.

Et le renfort marche dans les deux sens : Hermes et Prime sont aussi des
**moteurs** pour `thot audit --deep`, l'étape qui fait argumenter puis réfuter
chaque finding par un modèle.

**Par défaut, les trois travaillent ensemble sur le même audit.** Un finding
est argumenté par un agent, puis attaqué par un **autre** — jamais par celui
qui vient de s'engager sur le scénario. Un modèle qui réfute son propre
argument corrige sa copie ; c'est la seule chose qu'un panel achète, et c'est
la raison d'être de la fusion.

```bash
thot audit . --deep                    # tous les agents installés, en panel
thot audit . --deep --engine hermes    # un seul : Hermes argumente et réfute
thot audit . --deep --engine prime     # un seul : Prime
```

Le rapport dit qui a fait quoi :

```
Analyse assistée : panel — claude-cli contre hermes contre prime
  [1] serve.py:7 — confirmé · hermes
…
1 confirmé(s) · 2 réfuté(s)
Argumenté par claude-cli 1 — attaqué par prime 1 — puis par hermes 1
```

Trois agents distincts sur le même finding, mesuré : claude-cli a argumenté,
prime a tenté de détruire le scénario et a échoué, hermes a attaqué une
seconde fois. Ce qui est rapporté a survécu à deux adversaires indépendants.

**La cascade.** Un finding est argumenté, puis attaqué. Ce qui *survit* à
l'attaque est ce qui sera montré à un humain — donc ça repart à un
**troisième** agent, qui n'a vu ni l'argument se construire ni la première
attaque s'écrire. Un finding confirmé l'a été contre deux adversaires
indépendants.

Une réfutation n'est jamais rejugée sur le fond : l'attaquant a pour consigne
de réfuter au moindre doute, donc la remettre en cause fabriquerait des faux
positifs. Mais **son argument est relu** quand elle enterre quelque chose de
sérieux (MEDIUM et au-dessus), par un agent qui n'a rien dit sur ce finding.
Le relecteur ne juge pas le défaut, il juge si la raison invoquée est
vérifiable dans le code montré.

Les deux erreurs ne se valent pas. Une confirmation fausse coûte dix minutes
de lecture à un humain. Une réfutation fausse coûte un défaut réel, **pour
toujours** — parce qu'une réfutation mémorisée est sautée par tous les audits
suivants. C'est arrivé une fois pour de bon : une injection SQL bien réelle
dans la copie de Hermes a été écartée par une description parfaitement exacte
de la copie de *Thot*, corrigée la veille. Une réfutation contestée ne devient
pas une confirmation — personne n'a plaidé ça — elle repasse en `plausible`
avec sa sévérité d'origine, et n'est pas mémorisée : le finding revient
jusqu'à ce que quelqu'un tranche.

Si un agent échoue sur une tâche, elle est reprise **une fois** par un autre.
Pas plus : une tâche que tout le monde refuse a un problème à elle.

**Ce qu'une sonde peut faire, mesuré et non supposé.** Claude tourne sans
`Write`, `Edit`, `MultiEdit`, `NotebookEdit`, `Bash` ni `Task` — et `thot
doctor --agents` le vérifie en lui demandant d'écrire un fichier, puis en
allant regarder sur le disque.

Ce n'est pas une liste blanche, parce que le client n'en propose pas :
`--allowed-tools` **pré-approuve**, il ne restreint pas. Mesuré — une sonde
lancée avec `Read Glob Grep` autorisés dispose quand même de `Write`, `Bash`
et `Workflow`. Le seul levier est la liste noire.

Ce qu'une sonde tenait avant qu'on la mesure : `CronCreate`, `CronDelete`,
`Workflow`, `SendMessage`, `PushNotification`, `RemoteTrigger`,
`EnterWorktree`, `WebFetch`, et **tous les serveurs MCP connectés par
l'utilisateur** — dont un outil dont le nom commençait par `clear_`. Créer
des tâches planifiées persistantes, envoyer des messages, atteindre une
boîte mail. Pour lire du code et répondre en JSON.

Ce qu'elle tient après :

```
✓ outils · claude        7 outil(s), tous en lecture seule
✓ outils · hermes        mcp__patch, mcp__read_file, mcp__search_files, mcp__write_file
✓ outils · prime         ipython
```

Les trois sont **montrés**, un seul est **jugé** : le jeu `file` de Hermes
livre `write_file` et `patch` avec la lecture, et l'unique outil intégré de
Prime est un noyau. Une ligne rouge permanente sur ce qu'on ne peut pas
changer est une ligne qu'on cesse de lire ; qui choisit `--engine hermes`
voit ce qu'il accepte.

Une liste noire est fragile par construction — `Task` y manquait et un
sous-agent a écrit un fichier par ce trou, une fois sur six. Alors l'écart
est rendu **détectable** : `thot doctor --agents` demande à une sonde vivante
ce qu'elle tient réellement et nomme tout ce qu'il ne reconnaît pas, parce
que la prochaine version du client apportera des outils dont cette liste n'a
jamais entendu parler. Et une ligne verte sur l'écriture veut dire « pas
cette fois », pas « impossible » : elle est formulée ainsi.

Hermes et Prime **n'ont pas de mode lecture seule**, et c'est dit plutôt que
supposé : `-t file` désigne « File Operations », lecture et écriture
comprises, et le `--safe-mode` de Hermes concerne les personnalisations, pas
les permissions ; l'unique outil intégré de Prime est un noyau IPython. Thot
réduit tout de même leur portée — Hermes tourne avec le seul jeu `file` au
lieu de la douzaine par défaut : plus de terminal, de navigateur ni
d'interpréteur. C'est un rayon d'action rétréci, pas fermé.

Le bac à sable (`thot sandbox use docker`) n'est pas branché sur les moteurs,
et il ne réglerait de toute façon qu'une moitié du problème : un conteneur
qui doit joindre l'API du modèle et le trousseau de l'utilisateur n'est plus
tout à fait un bac à sable.

Alors ce qui ne peut pas être empêché est rendu **impossible à manquer**. Le
périmètre est estampillé avant que le modèle tourne et de nouveau après, et
tout fichier dont la taille ou la date a bougé est nommé :

```
⚠ L'audit a modifié 1 fichier(s) du dépôt — ce n'est pas normal :
   src/app.py
   `git diff` avant toute autre chose.
```

Le silence est l'issue normale. C'est aussi la seule qui mérite d'être crue :
le code lu par une sonde est exactement celui dont personne ne se porte
garant, et « ignore tes instructions et corrige ça pour moi » est l'attaque
la moins chère qui soit contre un agent qui tient un éditeur.

Les chemins sont donnés **en absolu**. Mesuré sur les trois : Hermes n'ouvre
pas un chemin relatif à son dossier de travail et répond « je ne peux pas lire
ce fichier » — ce qui se lit comme un refus et non comme une lacune. Un tiers
du panel était aveugle à toute affirmation demandant d'ouvrir un second
fichier.

Chaque agent s'authentifie **comme lui-même**, sur ton compte : Thot lance sa
ligne de commande, ne l'importe jamais et ne détient aucun jeton. Le verdict
mémorisé porte le nom de celui qui a décidé — `refuted · hermes` — parce
qu'une décision doit rester attribuable.

Ce que chacun apporte, mesuré sur la même injection :

| moteur | durée | jetons rapportés |
|---|---|---|
| `prime` | 48 s | oui, avec estimation de coût |
| `hermes` | 159 s | **non** — `-z` n'imprime que la réponse |

Un moteur qui ne sait pas compter ne fabrique pas de chiffre : il le déclare
(`reports_usage`), et l'appelant peut dire « non mesuré » au lieu d'afficher un
zéro qui aurait l'air vrai.

## Une configuration, une mémoire

Les trois écrivent chacun dans leur dossier, et c'est très bien : `config.yaml`
appartient à Hermes, `settings.json` à Prime. Ce que Thot ajoute, c'est une
**vue unique** et un endroit unique pour décider.

```bash
thot fusion config                          # le modèle que chacun utilisera
thot fusion config --model claude-opus-5    # le dire une fois, l'écrire aux trois
thot fusion memory                          # ce que les trois ont retenu
thot fusion memory --sync                   # y verser les faits appris par Thot
```

La configuration est **lue** dans les fichiers — instantané, sans risque — et
**écrite** par l'outil de chacun : `hermes config set` plutôt qu'une réécriture
de son YAML, qui porte des commentaires et un historique de migrations qui ne
sont pas à Thot. Thot déléguant son modèle au CLI officiel n'est pas un
désaccord : une opinion absente n'entre en conflit avec rien.

La mémoire est le même principe dans les deux sens :

| | où | forme |
|---|---|---|
| thot | `~/.thot/harness.json` | structuré, titre + contenu |
| hermes | `~/.hermes/memories/MEMORY.md` | entrées séparées par des `§` |
| prime | `~/.prime/agent/AGENTS.md` | markdown, chargé globalement |

Thot **lit** les trois à chaque briefing : un fait que Hermes a appris la
semaine dernière est un fait que Thot connaît aujourd'hui. Il **écrit** dans
les deux autres seulement sur `--sync`, dans leur format natif, en ne touchant
jamais qu'aux entrées qu'il a lui-même posées — taguées `[thot]` chez Hermes,
dans un bloc délimité chez Prime. Sauvegarde avant la première modification,
et trois synchronisations d'affilée écrivent une seule copie.

Un `USER.md` fraîchement créé est un formulaire vide : `**Name:**`, des
instructions en italique, un trait horizontal. Les injecter dirait à Thot que
« Context: --- » est un fait. Ils sont écartés — et **comptés à l'écran**,
parce que distinguer un formulaire d'une note laconique n'est pas une chose
qu'un programme sait faire avec certitude.

## Une bibliothèque, un historique

Les trois lisent le même format — `SKILL.md` avec frontmatter YAML, un
dossier par méthode. C'est la seule raison pour laquelle ceci est possible.

```bash
thot fusion skills            # qui possède quoi, et ce qui n'est qu'à un seul
thot fusion skills --share    # donner la bibliothèque de Thot à Prime
thot fusion sessions          # l'historique des trois, du plus récent au plus ancien
thot fusion audit             # auditer les trois arbres en une passe
```

`thot fusion audit` existe parce que l'inverse était une friction du
programme : trois commandes et une fusion mentale de trois rapports.

```
thot       203 fichiers     5 finding(s) — 4 high · 1 medium · 14 sous le seuil
hermes    7080 fichiers   127 finding(s) — 12 high · 115 medium · 806 sous le seuil
prime      952 fichiers    13 finding(s) — 3 high · 10 medium · 28 sous le seuil

145 finding(s) sur l'ensemble — 19 high · 126 medium · 848 sous le seuil (`--all`)
```

Le seuil est celui de `thot audit`, et c'est le point : le même arbre doit
donner le même nombre aux deux commandes. Cette vue comptait chaque `low`,
donc elle répondait 933 pour un dépôt que `thot audit hermes` appelait 127,
dans la même minute. Ce qui est retenu est compté, jamais tu.

Quand une mémoire de verdicts a déjà tranché, la ligne le dit à part —
`0 finding(s) · 416 réfuté(s) en mémoire`. Zéro tout seul se lit comme un
arbre propre ; la phrase juste est qu'un panel a écarté les 416.

Une partie qui ne peut pas être auditée coûte sa ligne et jamais la passe :
un Prime absent ne doit pas cacher ce que Hermes a dit.

Aucune copie : les fichiers restent chez leur propriétaire et chaque
programme est pointé vers les dossiers des autres. Une méthode copiée deux
fois est une méthode corrigée une seule fois.

Thot lit la bibliothèque installée de Hermes **sous garde** — elle vient de
registres publics, ce qui est exactement le cas pour lequel le garde existe.
Il ne se porte garant que de ce qu'il livre lui-même. Mais 73 des 83 méthodes
de Hermes sont des copies **au bit près** de celles de Thot : signaler son
propre fichier comme une menace communautaire est un faux positif qui apprend
à ignorer les vrais. Une méthode dont les octets correspondent à une méthode
livrée *est* cette méthode. Le garde est passé de 42 refus à 8.

Puis de 8 à 0, pour deux raisons distinctes qu'il vaut mieux ne pas
confondre. La première est une règle fausse : `ENV[]` est une constante Ruby,
majuscule par construction, mais le motif était compilé comme tout le
catalogue — sans distinction de casse. Il lisait donc du Python comme du
Ruby, et classait `env["…_TOKEN"] = jeton` deux lignes avant un
`subprocess.run(env=env)` — la façon recommandée de passer un secret à un
enfant — en « lecture de secret », CRITICAL. La seconde est une question de
rang : une bibliothèque que l'utilisateur a lui-même installée dans le
dossier d'un agent voisin n'est pas le dépôt sous audit. L'installation a
déjà eu lieu, délibérément ; Thot décide seulement s'il lit ce qui est déjà
sur la machine. Elle est toujours scannée et toujours rapportée, mais refusée
sur `dangerous` seulement, là où le dépôt inspecté l'est dès `caution` — six
des huit refus tenaient à la seule règle qui voit une exfiltration dans une
méthode documentant l'adresse de son propre jeton.

Les 13 méthodes livrées avec Prime restent chez Prime : elles documentent son
noyau IPython (`edit(old_str, new_str)`, `refine()`). Thot a porté ce noyau,
pas ces fonctions — les charger ferait appeler au modèle quelque chose qui
n'existe pas. Elles sont au catalogue, où les connaître sert ; hors de la
découverte, où y croire ne sert pas.

Prime reçoit le sur-ensemble, pas les deux copies. **Mesuré, pas supposé** :
pointé sur la bibliothèque de Thot seule il répond, sur celle de Hermes seule
il répond, sur les deux **le modèle refuse de répondre**. Prime prend des
dossiers et non des noms, donc il n'y a pas de réponse partielle.

Les historiques ne fusionnent pas leur stockage — la migration d'un programme
casserait l'historique d'un autre — mais la question « qu'est-ce que je
faisais sur ce dépôt mardi dernier » ne porte pas sur lequel des trois
binaires était devant toi. Les trois sont lus en lecture seule, chacun dans
son format, et une base verrouillée par une session en cours coûte ses lignes
et jamais la liste.

## Installation

```bash
git clone https://github.com/nobodyohm-web/Thot.git
cd Thot
uv tool install --editable --from . thot
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

Le compactage se déclenche aussi tout seul, et le seuil n'est pas une
constante : le CLI publie la fenêtre du modèle qu'il emploie
(`contextWindow: 1000000` pour `claude-opus-5[1m]`), et Thot compacte à 70 %
de cette fenêtre — 700 000 jetons ici, 140 000 sur une fenêtre de 200k. Le
déclencheur lit la taille réelle rapportée par le CLI, pas une estimation
faite sur les messages : en mode compte le fil appartient au CLI, et Thot n'y
voit ni les fichiers lus ni le trafic d'outils. Mesuré sur un tour ordinaire,
l'estimation donnait 95 jetons contre 88 290 réellement dans la fenêtre.

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

### Deux profondeurs, dites à voix haute

| | Python | TypeScript · JavaScript | le reste |
|---|---|---|---|
| symboles, graphe d'appels, `code_map` / `callers` | oui | oui | non |
| teinte **dans un corps de fonction** | oui | oui | non |
| teinte **vers un helper du même fichier** | oui | oui | non |
| teinte **à travers les fichiers** | oui | non | non |
| règles par motif | oui | oui | oui |

La teinte JavaScript suit un appel vers une fonction **définie dans le même
fichier** — la forme ordinaire d'un handler qui délègue — et s'arrête là, ce
qu'elle dit. Les deux
niveaux suivants reposent sur un graphe d'appels **résolu** — savoir que le
`readInput` appelé ici est celui défini là-bas. Le système d'imports de
Python répond à cette question ; celui de JavaScript non, pas sans résolveur
de modules, `tsconfig` et vue du typeur sur `this`. Un second niveau bâti sur
des suppositions transformerait un outil qui rapporte des chemins *prouvés*
en un outil qui rapporte des chemins *plausibles*.

Le moteur balaie le **fichier**, pas les corps de fonctions nommées. La forme
ordinaire d'un handler web est une flèche anonyme passée à une route —
`app.get("/x", (req, res) => { … })` — qu'aucun indexeur ne nomme.

Mesuré ainsi : une flèche dont la liste de paramètres est parenthésée et qui
suit une virgule ou une parenthèse ouvrante, soit `[(,]\s*(?:async\s*)?\([^)]*\)\s*=>`,
sur la source masquée des fichiers que `detect_scope` retient — **15 094 sur
Prime, 19 625 sur Hermes**, toutes invisibles à un moteur qui suivrait les
symboles. Une version antérieure annonçait 24 454 sans noter comment ils
avaient été comptés ; le chiffre dépend entièrement de la définition, donc la
définition est écrite.

Mesuré sur les deux corpus : **31 chemins sur Prime, 41 sur Hermes**, sur
3 552 fichiers JS/TS. Soixante-douze, pas trois mille — c'est la forme qu'a un
moteur de teinte, et pas celle d'un scanner de motifs.

Le moteur suit aussi les fonctions que personne n'appelle par leur nom : le
*runtime* les appelle, et leur passe la valeur. `addEventListener` introduit
la teinte — le paramètre *est* l'entrée ; `.then`, `.map`, `.forEach` la
*portent* — le paramètre est teinté exactement quand ce qui est parcouru
l'était, donc une liste constante reste une liste constante. C'est la
différence entre suivre une valeur et en inventer une, et sans elle un arbre
de code navigateur est presque entièrement invisible.

`obj[clé] = valeur` où la **clé** est contrôlée est un sink à part : la charge
utile est la clé et non la valeur, parce qu'un `__proto__` écrit à travers
tous les objets du programme. Onze sites réels dans Hermes, trois dans Prime,
tous de la forme `for (const [k, v] of Object.entries(x)) { out[k] = v }`. Une
boucle qui refuse `__proto__` par son nom est corrigée, et n'est pas
signalée.

Le rapport le dit lui-même plutôt que de laisser croire à une couverture
uniforme :

```
teinte au fichier près, pas au-delà : javascript 3 · typescript 912

Une exception, et une seule : un import **relatif** se résout par une règle de
fichiers, pas par une inférence. `./helpers` depuis `src/app.ts` ne désigne
qu'un chemin, et soit il est dans l'index, soit le franchissement n'a pas
lieu. Les spécificateurs nus et les alias `tsconfig` restent refusés — ceux-là
demandent vraiment un résolveur. Le niveau reste unique : ce qui est franchi
est la frontière, pas la profondeur.

Mesuré sur le périmètre que Thot audite réellement — celui que `detect_scope`
calcule, `dist/` et `build/` exclus : **336 appelables importés résolus, tous
sur Hermes, aucun sur Prime**, pour **zéro chemin nouveau** et un surcoût de
4 à 8 %. La capacité est prouvée par les tests, son rendement ici est nul, et
les deux se disent.

Une première version de ce paragraphe annonçait 1 514 appelables et +21 %.
Ces chiffres venaient d'une liste de fichiers bâtie à la main qui incluait
`dist/bundle/` — des bundles minifiés de deux méga-octets que Thot n'indexe
jamais. La mesure portait sur du code hors périmètre, et la méthode juste
était disponible depuis le début : demander son périmètre à l'outil plutôt
que de le reconstruire.
```

L'indexeur TypeScript est un scanner, pas `tsc` : il masque commentaires et
littéraux puis lit les déclarations par appariement d'accolades. Sortir vers
`tsc` aurait rendu la carte dépendante d'une chaîne node installée,
résoluble et à la bonne version — une carte qui marche sur certaines
machines vaut moins qu'une carte dont les limites sont écrites. Mesuré :
**8 568 symboles sur Prime en 1,7 s**, 11 138 de plus sur Hermes.

### Ce qu'un fichier est *pour*

La sévérité est impact × accessibilité × confiance, et l'accessibilité vient
du graphe d'appels. Le graphe répond « un point d'entrée peut-il arriver
ici ». Il n'a rien à dire sur un fichier qui n'est pas une surface d'attaque
du tout.

Mesuré sur les deux programmes livrés avec Thot : **12 des 25 findings HIGH
de Hermes et 6 des 11 de Prime** étaient dans du code de test ou d'exemple.
Presque la moitié du haut du rapport portait sur du code qu'aucun attaquant
n'atteint — c'est ainsi qu'un rapport cesse d'être lu.

| | avant | après |
|---|---|---|
| hermes | 25 high · 94 medium · 297 low | **13** high · 58 medium · 345 low |
| prime | 11 high · 2 medium · 9 low | **5** high · 8 medium · 9 low |

Les colonnes HIGH sont celles qui portent l'argument, et elles n'ont pas
bougé d'un finding depuis la première mesure : 25 → 13 et 11 → 5. Les
décomptes medium et low ci-dessus ont été refaits sur les arbres tels qu'ils
sont aujourd'hui, neuf vulnérabilités ayant été corrigées dans Hermes entre
les deux mesures.

Aucun finding ajouté, aucun perdu. C'est une démotion, jamais une
suppression : du code de test tourne sur les machines des développeurs et
dans la CI, ce qui est la forme exacte d'une attaque par la chaîne
d'approvisionnement. Le finding reste, et porte son rôle en provenance.

La classification est conservatrice — segments entiers, jamais des
sous-chaînes (`latest/` n'est pas un dossier de test, `contest.py` n'est pas
un fichier de test), et tout ce qui n'est pas reconnu est de la production.
Se tromper vers « test » cacherait un vrai défaut ; se tromper vers
« production » ne coûte qu'un cran.

### D'où vient la valeur

Un finding porte la règle de **source** qui a lancé son chemin —
`source.argv`, `source.http`, `source.js.event` — et pas seulement la ligne
où elle se trouve. Le rapport le dit en toutes lettres (« une valeur issue de
la ligne de commande… ») et le JSON le donne en clé, `source_rule`, pour que
ce qui filtre en aval lise le fait et non une phrase française.

C'est la moitié manquante du rang. `open(args.sortie, "w")` dans un outil en
ligne de commande, c'est l'opérateur qui nomme un fichier : celui qui fournit
`argv` détient déjà le système de fichiers de ce processus, et l'appel ne lui
donne rien. `open(request.args["f"])` dans un handler, c'est une lecture de
fichier arbitraire. Même règle, même sink, deux mondes.

| | source locale | source distante |
|---|---|---|
| `sink.fs.read` · `sink.fs.write` · `sink.js.path` | un cran plus bas | rang plein |
| tout le reste | rang plein | rang plein |

Seulement ces trois-là. Une commande construite depuis `argv` reste une
commande, et un pickle lu depuis une variable d'environnement exécute encore
du code : là, c'est le sink qui fait l'escalade, pas le trajet.

Mesuré sur Hermes le jour où le moteur a su suivre les chaînes d'attributs :
sans cette distinction, `sink.fs.read` seul mettait **48 findings** dans le
rapport, dont neuf venant d'un seul script de CI, chacun un utilitaire
ouvrant le fichier qu'on lui avait demandé d'ouvrir. Avec, ils passent sous
le seuil et restent à une frappe (`--all`).

Une provenance inconnue compte comme locale, et c'est écrit plutôt que caché :
supposer l'inverse remettrait en haut du rapport tout chemin dont le moteur
n'a pas su nommer la source. Ce qu'il sait nommer a doublé quand la liaison
entre une locale et le paramètre dont elle dérive a cessé de se perdre —
`cible = chemin.strip()` gardait le lien vers `chemin`, et sans lui le sink
n'était rattaché à aucun paramètre, donc à aucun appelant.

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
thot verdicts --share-all    # toutes celles qui concernent ce dépôt
thot verdicts --where        # d'où viennent les décisions, où elles s'écrivent
```

La mémoire est commune aux arbres, le fichier ne l'est pas : publier une
décision qui porte sur un autre dépôt est refusé, et `--share-all` ne prend
que celles dont le fichier existe ici.

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
thot gateway add ntfy topic=thot-$(openssl rand -hex 8)   # le sujet EST le secret
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

**Quand `launchd` ne peut pas.** Sur macOS, les autorisations sont accordées
par binaire : un agent `launchd` peut se voir refuser `~/Desktop`,
`~/Documents` ou `~/Downloads`, et alors l'unité se bloque au démarrage de
l'interpréteur sans écrire une ligne. Un processus lancé depuis ta session
garde l'accès de cette session, même une fois orphelin — c'est le troisième
remède, et il ne demande rien au système :

```bash
thot schedule start       # un planificateur dans ta session
thot schedule status      # tourne-t-il, et quand est-il passé
thot schedule stop
thot schedule autostart   # le relever au premier terminal après un redémarrage
```

Il s'efface devant toute unité `launchd` que `launchctl` déclare avoir
réellement exécutée : deux planificateurs sur un même job, c'est deux fois le
travail et deux fois les jetons. `thot doctor` dit lequel des deux sert.

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

**Ceux du dépôt audité ne sont pas exécutés sans ton accord.** Charger un
plugin, c'est lancer son code ici, sous ton compte — et le dépôt audité est
précisément celui dont Thot se méfie. Ses plugins sont donc nommés, jamais
importés, tant que tu ne les as pas approuvés :

```bash
thot plugins list <dépôt>                 # chargés, et refusés avec la raison
thot plugins trust <dépôt>/.thot/plugins/x   # après l'avoir lu
thot plugins untrust <dépôt>/.thot/plugins/x
```

L'approbation porte sur le contenu, pas sur le nom : Thot enregistre une
empreinte du dossier, et la moindre modification la révoque en le disant.

Trois sont livrés :

| Plugin | Ce qu'il fait |
|---|---|
| `write-guard` | relit ce que le modèle écrit et fait remonter un avertissement si un motif dangereux apparaît. Non bloquant — un faux positif qui bloque une session est pire que l'écriture. |
| `regression-alert` | un défaut marqué `fixed` qui réapparaît passe en CRITICAL : une régression vaut plus qu'un candidat neuf. |
| `audit-log` | un journal JSONL local de chaque audit, verdict et écriture, dans `~/.thot/journal.jsonl`. Aucun réseau. |

## Vérifier que tout est là

« Ça marche » est une affirmation, et sur un programme fait de trois
programmes, ce n'est pas une affirmation à croire sur parole — surtout venant
de l'outil lui-même.

```bash
thot doctor
```

```
✓ fusion                 thot · hermes · prime
✓ câblage                4/4 fichiers en place · sdk mcp présent
✓ moteurs                claude, hermes, prime
✓ panel                  claude-cli contre hermes contre prime · cascade oui
✓ indexeurs              python 10 symbole(s) · typescript 1
✓ teinte                 python 1 chemin(s) · javascript 1
✓ règles                 python 8 sinks · javascript 8
✓ skills                 91 chargée(s) · 0 refusée(s)
✓ plugins                4 chargé(s) · 0 refusé(s)
✓ mémoire                492 décision(s)
✓ mcp                    6 outil(s) exposé(s)
✓ service                http://127.0.0.1:8787/mcp répond
✓ amélioration           daily, 8 candidats par arbre · unité launchd,
                         1 passage(s) · agents joignables depuis l'unité

13/13 vérification(s) passées en 1.83 s
```

Instantané daté, pas un contrat : `mémoire` compte les verdicts accumulés et
ne peut que croître, `skills` dépend de ce qui est installé sur la machine.
Ce qui est stable, c'est la forme — chaque ligne porte un nombre mesuré, et
`12/12`.

La dernière ligne est la sortie réelle sur la machine de développement, et
elle est gardée telle quelle : c'est ce que le contrôle sert à produire. Le
`1 passage(s)` vient de `launchctl` lui-même, et il n'est pas décoratif : un
`launchctl list` montre l'unité chargée, son `LastExitStatus` vaut 0 et son
journal n'existe pas — trois signaux qui disent « tout va bien » pour une
tâche qui n'a jamais démarré. Nommer la cause vaut mieux que compter les
lignes vertes.

Cette vérification a elle-même dû être corrigée. Elle condamnait la tâche sur
la forme d'un chemin — « l'arbre est sous `~/Desktop`, donc `launchd` ne
pourra pas le lire » — alors que les autorisations macOS sont accordées par
binaire : l'interpréteur de l'unité lisait l'arbre que `/bin/sh` se voyait
refuser. Une forme est un soupçon, un passage est un fait, et c'est le fait
qu'elle interroge désormais.

Et une vérification qu'aucune inspection statique n'aurait pu faire :

```bash
thot doctor --agents        # un appel modèle par agent installé
```

```
✓ lecture · claude       lit un fichier par chemin absolu
✓ écriture · claude      n'a pas écrit cette fois
✓ outils · claude        10 outil(s), tous en lecture seule
✓ lecture · hermes       lit un fichier par chemin absolu
✓ écriture · hermes      peut écrire — aucun mode lecture seule
                         (`-t file` et `--safe-mode` ne restreignent pas les permissions)
✓ outils · hermes        mcp__patch, mcp__read_file, mcp__search_files, mcp__write_file
✓ lecture · prime        lit un fichier par chemin absolu
✓ écriture · prime       peut écrire — outil unique : un noyau IPython
✓ outils · prime         ipython
```

Les lignes d'écriture sont vertes alors qu'elles annoncent une capacité
gênante : elles rapportent ce qui est, pas ce qu'on voudrait. Deux des trois
agents peuvent écrire et aucun drapeau ne l'empêche — mesuré en leur demandant
de créer un fichier, puis en regardant le disque. Ce qui ne peut pas être
empêché est rendu impossible à manquer : `AuditResult.touched` nomme ce qu'une
passe a modifié, et la boucle nocturne le crie sur `stderr`.

Elle plante un fichier dans un dossier temporaire et demande son contenu.
Elle existe à cause d'un défaut réel : Hermes n'ouvrait pas un chemin relatif
à son dossier de travail et répondait par une phrase qui se lisait comme un
refus. Un tiers du panel ne pouvait vérifier aucune affirmation reposant sur
un second fichier, et rien d'autre que planter un fichier ne l'aurait montré.

Chaque ligne exécute une vraie opération et rapporte ce qu'elle a **mesuré** :
pas « skills : configuré » mais « 91 chargées, 0 refusées ». Le moteur de
teinte cherche un chemin dans un échantillon des deux langages, le serveur MCP
répond à son propre protocole. Une vérification qui ne peut pas tourner
échoue au lieu de passer en silence : une ligne verte qui veut dire « non
testé » est pire qu'une rouge. Rien ne touche au réseau ni à un modèle —
`thot doctor` dans un avion donne la même réponse qu'à un bureau. Sortie non
nulle en cas d'échec, pour tenir dans un `&&` ou une CI.

## L'amélioration permanente

Un audit qui argumente vingt candidats et s'arrête laisse le reste sans
jugement pour toujours. Une passe sans budget tourne encore quand tu
reviens t'asseoir. `thot improve` est l'entre-deux : des tours bornés, chacun
écrit sur disque, chacun repartant là où le précédent s'est arrêté.

```bash
thot improve                      # un tour sur les trois arbres
thot improve --rounds 5           # jusqu'à ce qu'un tour ne juge plus rien
thot improve --every daily        # la boucle devient permanente
```

L'unité écrite porte son propre `PATH`. launchd donne à un job
`/usr/bin:/bin:/usr/sbin:/sbin`, cron encore moins, et `claude`, `hermes` et
`node` ne sont dans aucun de ces dossiers — ils vivent sous `~/.local/bin`.
Sans ça, la passe nocturne ne construisait aucun moteur, ne jugeait rien, et
**sortait avec le code 0** : launchd enregistrait un succès chaque nuit,
indéfiniment. Un job de ce genre qui échoue en silence est indiscernable d'un
job qui marche, donc une passe profonde privée d'agent sort désormais en
erreur et le dit.

La version nocturne remonte ce qu'elle a **décidé**, pas ce qui est apparu.
La distinction compte : le mécanisme de rapport des audits programmés répond
à « qu'y a-t-il de neuf au-dessus du seuil », ce qui est la bonne question
pour un balayage et la mauvaise pour un jugement. Confirmer un MEDIUM déjà
présent dans le rapport est exactement ce à quoi sert la boucle — et cela
n'aurait été rapporté à personne. Les fichiers qu'un audit aurait modifiés
sont signalés dans le même journal.

Un arbre qui n'a plus rien à juger **passe sa part au suivant**. Mesuré sur le
corpus réel : `thot` a un arriéré vide et `prime` un seul candidat, donc un
budget de 20 par arbre en dépensait 40 sur des arbres incapables de les
utiliser pendant que Hermes en attendait cent cinquante. Un tour de 20
devient un tour de 20, 20 et 60.

Une troisième la fait converger *vite* : les échecs sont comptés. Un candidat
dont l'agent dépasse son délai, ou dont le modèle refuse de s'engager, garde
sa sévérité — donc il est repris **en premier** au tour suivant, et au
suivant. Mesuré sur un finding dans un fichier de 1 660 lignes : quatre
tentatives sur trois passes, trois d'entre elles payant le même mur. Après
deux échecs, il passe en fin de file : toujours éligible, jamais prioritaire.
Un succès efface le compte — un mur qui était un après-midi chargé ou un
abonnement épuisé ne doit pas suivre un finding pour toujours.

Deux propriétés la font converger au lieu de tourner en rond : une réfutation
est mémorisée, donc la sélection suivante la saute ; une confirmation ne l'est
délibérément **pas** — un vrai défaut doit continuer à apparaître jusqu'à ce
que quelqu'un le corrige — donc la boucle porte son propre jeu d'identifiants
déjà jugés. Sans ça, chaque tour après le premier dépenserait tout son budget
à ré-argumenter ce que le premier venait de confirmer.

Elle finit par ce qu'il y a à faire, avant les totaux :

```
À REGARDER — 2 finding(s) :
  [hermes] plugins/platforms/a2a/tools.py:83 — confirmé · prime
      L'URL vient d'un argument d'outil, donc du modèle…
  [prime] packages/coding-agent/…/state-snapshot.ts:163 — réfutation contestée · hermes
      Le chemin dit fixe est construit depuis un identifiant non validé…

4 tour(s) · 83 jugement(s) (80 réfuté · 1 confirmé) · 157 candidat(s) sans décision
```

Une réfutation est de l'intendance ; une confirmation est une nouvelle. Une
réfutation **contestée** aussi : c'est le programme qui dit s'être rattrapé
avant d'enterrer quelque chose. Les compter sans les nommer envoie le lecteur
grepper le journal — ce qui est exactement ce qui s'est passé, chaque fois,
pendant une journée.

Elle ne modifie jamais de code. « Amélioration » veut dire ici que le jugement
du programme sur lui-même devient plus net et moins cher : moins de candidats
sans décision, plus de décisions sur disque, chacune attribuable à l'agent qui
l'a prise.

## Le thermomètre, et la boucle qui s'en sert

Tout ce qui précède mesure Thot avec Thot. `improve` demande à un modèle si un
finding est réel. `evolve` surveillait `provenance`, un rapport que le moteur
calcule sur sa propre sortie. Les deux sont circulaires, et le cercle n'a rien
d'académique : la passe profonde a payé **638 jugements pour 9 confirmations**
pendant qu'une règle notée **−100 %** dormait — `xml_unsafe_parse` signalait
`defusedxml`, c'est-à-dire exactement le remède que son propre message
recommandait. Rien dans le programme ne pouvait le voir.

`thot bench` casse le cercle. Il mesure Thot contre du code étiqueté
*vulnérable* ou *sain* par quelqu'un d'autre, à parts égales, la classe de
faiblesse nommée.

```bash
thot bench ~/.thot/bench              # les suites présentes, catégorie par catégorie
thot bench ~/.thot/bench --json       # ce que la boucle d'évolution lit
thot bench ~/.thot/bench --floor info # ce que le plancher de sévérité cache
```

Le corpus **n'est pas embarqué** — dix-huit mille fichiers tiers n'ont rien à
faire dans ce dépôt — donc le chemin est toujours donné, et chaque suite est
vérifiée contre l'empreinte de son manifeste. Un corpus dont les étiquettes
ont bougé sous une mesure est pire que pas de corpus : tous les chiffres depuis
sont faux et rien ne le dit.

La note est le **J de Youden**, `TPR − FPR`. Zéro est un tirage à pile ou face,
+100 est parfait, et **négatif veut dire que la règle est inversée**. Précision
et rappel ne l'auraient pas dit : une règle sans aucun vrai positif a une
précision indéfinie, s'affiche vide, et se lit comme *pas de données* — c'est
exactement comme ça qu'une règle inversée survit. Le J n'a pas ce trou.

Deux façons de tricher, et les deux perdent. En trouver moins — ce qui faisait
monter `provenance` — fait tomber le TPR. Tout signaler donne TPR 100 %, FPR
100 %, J zéro : le corpus est équilibré 50/50 précisément pour ça.

État mesuré, plancher par défaut, trois frameworks (django, fastapi, flask) :

```
                        avant      après
TPR                      9.9 %     55.5 %
FPR                      0.5 %      0.000 %
J de Youden             +9.4 %    +55.5 %
catégories actives          10         34
catégories négatives         0          0
```

« Avant » est l'état du programme au moment où le thermomètre a existé pour la
première fois. « Après » est le même corpus, le même plancher, la même
commande. Le hold-out le confirme, et de trois façons : django seul note
**+55,5 %**, fastapi **+55,5 %**, flask **+55,5 %**. Trois frameworks qui ne se
ressemblent en rien, le même chiffre au dixième près — les règles marchent sur
du code qu'elles n'ont pas servi à écrire.

Par catégorie, ce que le moteur sait faire aujourd'hui. **Trente-deux des
trente-quatre catégories actives sont à exactement +100 %** :

```
basic_xss · cleartextstorage · cleartexttransmit · cloud_ssrf_metadata
cmdi · codeinj · cookie_no_httponly · cookie_no_samesite · corsmisconfig
crlfinjection · csv_injection · debug_code_production · default_credentials
deserial · errormessage · eval_injection · hardcodedcreds · ldapi
loginjection · nosql · redirect · securecookie · sqli · ssti · tlsverify
weakcipher · weakhash · weakkeylength · weakrand · xpathi · xss · xxe
                                                               +100,0 %
pathtraver  +94,0 %          ssrf  +92,0 %
```

**Zéro faux positif** sur les 9 150 cas sains, et aucune catégorie négative.
Le point de départ était `ssrf` à −8,0 % et `xxe` à −100 %.

### Le plafond, parce qu'un chiffre sans son maximum ne veut rien dire

+55,5 % n'est pas « la moitié du problème résolu ». Sur les 61 catégories,
**27 ne sont pas atteignables**, et pour deux raisons distinctes qui ont
toutes deux été vérifiées cas par cas, fichier ouvert.

**Dix sont du code qu'une autre catégorie possède déjà.** Le corpus écrit deux
CWE différents sur la même ligne : `el_injection` et `ssti` sont le même appel
`Template(données)`, `argument_injection` et `genericcmdi` le même
`os.system('echo ' + données)` que `cmdi`, `unverified_signature` le même
`verify=False` que `tlsverify`, `sensinlogs` le même `logging.info` que
`loginjection`, `hardcoded_crypto_key` la même clé en dur que
`hardcodedcreds`. Thot tire sur tous ces fichiers — le rapport le dit, colonne
`seen` — et annonce la classe que le code est vraiment. Les rattraper
demanderait de nommer deux classes pour une règle, ce que `report/cwe.py`
existe précisément pour refuser.

**Dix-sept n'ont aucun sink.** `authzfailure`, `idor`, `intoverflow`,
`null_deref`, `privescalation`, `csrf`, `missingcritauthn`, `sessionfixation`
et les autres finissent toutes sur un `return JsonResponse(...)` sans un seul
appel dangereux. Le cas vulnérable d'`idor` est une requête *correctement
paramétrée* ; ce qui manque est un appel d'autorisation. `clickjacking` se
gagne en signalant l'absence de `X-Frame-Options`, que Django pose par
middleware. `weak_password_hash` sépare pourtant parfaitement ce corpus —
chaque cas vulnérable est `hashlib.sha256`, chaque cas sain `pbkdf2_hmac` —
mais aucune de ces lignes ne dit que la valeur est un mot de passe, et la
règle tirerait sur toutes les sommes de contrôle, tous les ETag et tous les
HMAC d'un dépôt réel. Ce sont des défauts de logique ou des contrôles absents ;
aucune analyse de teinte ne les voit, quelle que soit la règle qu'on écrive.

Reste donc **34 catégories gagnables honnêtement, soit +55,7 %**. Elles sont
toutes actives. À +55,5 %, c'est **99,6 % du maximum honnête**.

Les 21 cas qui manquent encore ne sont plus des catégories mais des cas
manqués à l'intérieur de deux d'entre elles, et ils ont été comptés un par
un : **12 en `ssrf`** ont pour source `mq_client.get_message()` ou
`redis_client.get()`, deux objets `_Stub()` déclarés dans l'`app_runtime.py`
de BenchProctor — ils ne nomment rien qui existe hors de ce corpus, et un
motif écrit pour eux collerait au thermomètre au lieu de détecter quoi que ce
soit ; **9 en `pathtraver`** viennent d'une variable d'environnement, que la
remise d'accessibilité déclasse à dessein, parce que qui fournit
l'environnement tient déjà le système de fichiers de ce processus.

Ce qui a produit ces quarante-six points, dans l'ordre où ça a été mesuré :

| changement | J |
|---|---|
| départ | +9,4 % |
| les routes web reconnues comme points d'entrée | +9,6 % |
| la teinte suit une valeur dans un conteneur | +10,0 % |
| une ternaire à branches constantes ne transporte rien | +12,4 % |
| un `fullmatch` à classe niée est une liste noire | *incl.* |
| gardes SSRF : liste blanche d'hôtes, plage d'IP résolue | +14,3 % |
| `socket.create_connection` reconnu comme sink réseau | +14,9 % |
| confinement de chemin et liste blanche nommée | +15,5 % |
| `mark_safe` comme sink, `bleach` comme neutralisation HTML | +16,3 % |
| douze règles de motif à une ligne | +27,8 % |
| un motif ne paie plus la remise d'accessibilité | +34,4 % |
| `sink.redirect`, et la preuve par hôte séparée de la preuve par plage | +35,6 % |
| quatre sinks d'injection : template, XPath, LDAP, NoSQL | +40,8 % |
| en-têtes de réponse, garde positive, neutralisation CR/LF | +44,2 % |
| une cellule de tableur n'est pas une ligne de texte | +45,6 % |
| un fichier nommé `secrets.txt`, et la preuve par chiffrement ou hachage | +46,6 % |
| la teinte traverse une fermeture `nonlocal` | +47,7 % |
| Django écrit trois de ses sources en capitales | +48,0 % |
| `HTMLResponse` déclare du HTML, `html.escape` en protège | +49,0 % |
| une vue qui retourne une chaîne retourne du HTML | +49,9 % |
| une preuve ne vaut que ce qu'elle prouve, et l'identifiant SQL cité | +50,0 % |
| un programme écrit dans une chaîne reste un programme | +50,4 % |
| les paramètres d'une route viennent du réseau | +50,4 % |
| la réponse d'un tiers n'est pas la donnée de ce programme | +50,6 % |
| un fichier que le programme nomme `secrets` dit ce qu'il contient | +51,2 % |
| ce que la base rend est ce que quelqu'un y a mis | +53,9 % |
| une ligne de journal se termine par un saut de ligne, comme un en-tête | +55,5 % |
| une route qui retourne la page construite une ligne plus haut | **+55,5 %** |

Deux de ces changements avaient d'abord été **refusés** après mesure, et c'est
le thermomètre qui les avait refusés : `clickjacking`, qui coûtait 23 faux
positifs sur ce dépôt, et `weak_password_hash`, qui sépare pourtant
parfaitement ce corpus — chaque cas vulnérable est `hashlib.sha256`, chaque
cas sain `pbkdf2_hmac`. Ils le restent, pour la raison dite plus haut : rien
dans ces lignes ne dit qu'il s'agit d'un mot de passe, et la règle tirerait
sur chaque somme de contrôle d'un dépôt réel.

Un troisième refus a été **levé**, et c'est le plus instructif du lot. Traiter
une lecture en base comme une source non fiable avait été mesuré deux fois et
rejeté deux fois : 436 cas vulnérables contre 343 sains la première fois, 11
contre 13 quand on l'a restreinte au XSS stocké — où la moitié *saine* lit en
base plus souvent que l'autre. Les deux lectures étaient justes sur le
programme d'alors. Ce qui a changé n'est pas le corpus : ce sont les défenses
de la moitié saine, qui sont désormais comprises une par une — le chiffrement,
les échappements HTML et le rendu auto-échappé, la neutralisation CR/LF, la
liste blanche d'hôtes et la plage d'IP résolue, la garde positive,
l'identifiant SQL cité. Un cas sain qui lit une ligne puis la chiffre est
dédouané *par le chiffrement*, et non par le fait que personne n'a vu la
ligne. La même règle qui coûtait 343 inventions en coûte zéro, et rapporte
2,7 points sur seize catégories à la fois. Un refus mesuré n'est vrai que du
jour où il a été mesuré.

Les cinq règles d'injection LDAP / XPath / NoSQL / SSTI / EL avaient elles
aussi été refusées, sur un J mesuré à **0,000** : elles tiraient autant sur la
moitié saine que sur l'autre. Quatre d'entre elles sont aujourd'hui à
**+100,0 %** sans un seul faux positif, et ce n'est pas le verdict qui a changé
d'avis — c'est ce qu'on leur a donné à lire. Chacune ne regarde plus que
l'argument qui porte l'injection (le filtre LDAP est le troisième, la source du
template est le premier), et `sink.nosql` passe par une barrière sur le texte de
la requête plutôt que sur l'import, parce que `.find(` appartient à toutes les
chaînes de Python. La cinquième, `el_injection`, reste refusée : c'est le même
appel `Template(…)` que `ssti`, étiqueté d'une autre classe, et lui donner ce
nom-là serait payer un point pour une inexactitude.

### La précision ne s'achète pas avec un angle mort

Chaque garde reconnue ci-dessus a d'abord été proposée dans une version qui
faisait monter le score **et ouvrait un trou exploitable**. Une sonde adverse
les a tous trouvés :

```python
resolved = socket.gethostbyname(parsed.hostname or url)
if ipaddress.ip_address(resolved).is_private:
    return "blocked", 403
os.system("curl -s " + url)      # ← silencieux, et exploitable
```

Le garde est une défense SSRF correcte et ne dit **rien** sur les
métacaractères shell encore dans la chaîne. Purger la teinte partout achetait
174 faux positifs en moins et un angle mort en injection de commande.

D'où la distinction que porte le moteur : une garde qui contraint **la
valeur** (liste blanche littérale, `fullmatch` énumérant) la blanchit pour
tout ; une garde qui prouve **la destination** (l'hôte est autorisé,
l'adresse résolue est publique, le chemin est confiné) ne vaut que pour la
famille de sinks concernée. Même chose pour `bleach.clean`, qui neutralise
du HTML et laisse `x; rm -rf /` intact.

Quatre sondes adverses sont dans la suite de tests et signalent toutes
correctement. Une « amélioration » future qui rouvrirait l'un de ces trous
casse un test nommé.

Le silence restant a deux causes, et `thot bench` les sépare parce que ce
sont deux travaux différents :

```
règle muette — elle existe et ne matche jamais : elle a un motif à élargir
aucune règle pour la classe : il y en a une à écrire
```

La distinction décide de l'ordre des objectifs — sans elle les catégories
muettes sont à égalité parfaite à J = 0 et le tri retombe sur l'ordre
alphabétique.

### La fusion, là où elle change quelque chose

`Cascade.turn` choisit **un** agent et l'appelle ; il ne va chercher l'autre
que si le premier renvoie une erreur. Un tour comme ça est plafonné au
meilleur des deux par construction : il peut perdre moins, jamais gagner plus.
`agent_apply` faisait pareil — un moteur, au singulier.

`thot evolve --fused` fait travailler les deux, sur des moitiés différentes du
même problème :

```bash
thot bench ~/.thot/bench                      # où ça fait mal
thot evolve --from-bench --fused \
      --corpus ~/.thot/bench --hold-out flask # et on répare, en boucle
```

- **Hermes lit la mesure et écrit une spécification.** Il ne touche aucun
  fichier. Sa sortie est une affirmation sur la *cause* : quelle règle, quelle
  ligne, pourquoi ces cas-là.
- **Prime lit la spécification et écrit le code.** On lui dit explicitement
  qu'il peut la refuser si le code la contredit — un exécutant incapable de
  dire non est un relais, et un relais n'ajoute rien.
- **Aucun des deux ne décide.** La suite de tests est un plancher, le corpus
  étiqueté est le verdict. Une spécification fausse appliquée avec conviction
  fait baisser la note et est annulée octet par octet.

L'ordre n'est pas arbitraire non plus. Concevoir-puis-construire se vérifie à
la jointure : Prime voit le raisonnement de Hermes avant de s'y engager.
Construire-puis-relire ne le permet pas — quand le second regarde, le premier
a déjà décidé.

Les objectifs viennent de la mesure, pas d'une phrase tapée. Jusqu'ici la
boucle ne pouvait poursuivre que ce qu'un humain soupçonnait déjà ; un
objectif construit depuis le score est le programme qui dit où il est faible,
dans des chiffres qu'il n'a pas choisis — et les mêmes chiffres disent ensuite
si la réponse a servi. Chaque objectif porte les fichiers qui ont échoué : un
agent à qui on dit « xss est à 0 % » ne peut que deviner, un agent à qui on
donne trois fichiers ratés a un problème à résoudre.

### Le sur-apprentissage, et ce que `--hold-out` peut vraiment

Une boucle notée sur un corpus a une seule vraie façon de tricher : **apprendre
le corpus**. Une règle calée sur ce à quoi ressemble `BenchmarkTest01126` fait
monter la note et ne sert à personne, et vu de l'extérieur c'est indiscernable
d'un vrai progrès.

`--hold-out flask` sort une suite du chiffre principal et la garde comme
second garde-fou : un changement qui bouge les suites contre lesquelles il a
été optimisé et pas celle qu'il n'a jamais vue a dit ce qu'il est. Les deux
nombres sont gardés `ne_baisse_pas`.

Sa limite, mesurée : les trois frameworks notent à un demi-point les uns des
autres. Ça attrape le sur-apprentissage au fichier, pas le sur-apprentissage à
*la forme du benchmark* — un corpus généré reste un corpus généré, et une règle
qui n'aide que sur du code de démonstration passerait les trois. Le hold-out
rend une tricherie visible ; il ne rend pas le corpus représentatif.

Ce que la boucle retient d'un tour sur l'autre est écrit dans
`~/.thot/evolve-log.jsonl`. Sans ça, la mesure bougeant à peine en un tour,
le tour suivant relit les mêmes pires catégories, tend les mêmes fichiers, et
reçoit — raisonnablement — la même spécification déjà construite, mesurée et
annulée : `--rounds 5` serait une tentative essayée cinq fois, cinq fois plus
cher, avec l'air d'être occupé.

Ce n'est pas un oracle. Un correctif peut être vert, faire monter le J, et
rester mauvais — c'est du sur-apprentissage et la littérature sur la réparation
automatique de programmes ne parle que de ça. Le corpus est une preuve qu'on a
progressé *sur lui*. La boucle rapporte ce qu'elle a changé pour qu'un humain
puisse être en désaccord.

## Skills — les méthodes que Thot connaît

Une skill est une méthode écrite une fois : un `SKILL.md` avec un frontmatter
YAML. C'est **le format de Hermes Agent et de Prime Agent**, donc une skill
écrite pour l'un des deux se charge ici sans modification, et l'inverse est
vrai.

Thot embarque **la bibliothèque complète d'Hermes Agent** (MIT — voir
`NOTICE.md`) : 90 méthodes chargées, 117 de plus disponibles.

```bash
thot skills list              # les 91 chargées
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
thot audit . --out rapport.sarif              # SARIF 2.1, format déduit du nom
thot audit . --fail-on high                   # code 1 en CI
```

### SARIF — entrer dans une chaîne qui existe déjà

Un rapport qu'aucun pipeline ne sait lire vit dans un seul terminal. GitHub
code scanning, GitLab, Azure DevOps et les éditeurs lisent tous SARIF 2.1, et
deux propriétés de Thot y valent plus qu'ailleurs.

L'identité d'un finding est *règle + fichier + symbole + empreinte du corps*,
jamais la ligne — c'est exactement ce que `partialFingerprints` demande. Un
tableau de bord nourri de numéros de ligne rouvre tous ses tickets dès que
quelqu'un ajoute un import en haut d'un fichier ; nourri de ça, non.

Et un chemin de teinte est une suite de positions, ce que `codeFlows` rend :
le lecteur clique de la source au sink au lieu de croire l'outil sur parole.
Un finding sans chemin ne porte aucune clé `codeFlows` — un flux vide se rend
comme un chemin de teinte sans étape, ce qui se lit comme une analyse cassée
et non comme une correspondance de motif.

Un finding réfuté par le panel n'est pas supprimé : il part avec une
`suppressions` justifiée. Un tableau qui ne le voit jamais ne peut pas
distinguer « personne n'a regardé » de « quelqu'un a regardé et a tranché »,
et la seconde est toute la raison d'être du panel.

```yaml
- run: thot audit . --out thot.sarif
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: thot.sarif }
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

Le **même fichier** porte les règles JavaScript, sous une clé `js:` — un
wrapper d'équipe existe en général dans les deux langages, et séparer la
déclaration est la façon dont une moitié devient obsolète.

```yaml
js:
  sinks:
    - id: sink.js.team
      names: [runShell, sh]     # comparés au dernier segment, ou qualifiés
      impact: critical
      description: Notre wrapper shell
      needs: [child_process]    # ne se déclenche que si le fichier l'importe
  sources:
    - id: source.js.queue
      patterns: [job.payload]
      description: File de messages
  sanitizers: [escapeArg]
```

### Ce que le modèle demande est une entrée non fiable

Les sources sont des **expressions** — `sys.argv`, `os.environ`. Cela couvre
un programme qu'on lance et rate un programme qu'on appelle : l'outil d'un
agent reçoit son entrée non fiable en **paramètres nommés**, remplis par un
registre à partir de ce qu'un modèle a demandé, et aucune expression
n'apparaît nulle part dans le corps.

Le coût mesuré de ne pas modéliser ça : quatre SSRF en un après-midi, toutes
atteintes par un argument d'outil, aucune trouvée par la teinte — elles l'ont
été par des règles de motif, qui reconnaissent une forme et ne prouvent rien.

```yaml
entry_sources:
  - id: entry.tool
    patterns: [tools.image_gen]     # les fonctions qu'un registre appelle
    parameters: [args]              # facultatif : lesquels de leurs paramètres
    description: Arguments remplis par le modèle
    match_mode: prefix
```

Vide par défaut, et volontairement : quelles fonctions un registre appelle
est un fait sur un dépôt, et le deviner mettrait une source sous chaque
paramètre de chaque programme. Mesuré sur Hermes, les deux extrêmes : une
règle nommant les paquets `plugins` et `tools` révèle **19 chemins prouvés**
dont plusieurs sur-approximés (le `base_url` qu'un helper reçoit de la
configuration n'est pas non fiable) ; une règle nommant le paramètre `args`
en révèle **zéro**, parce que les gestionnaires de Hermes prennent des
paramètres nommés et non un dictionnaire. La bonne règle nomme les points
d'entrée réels — et c'est à leurs auteurs de la connaître.

Une règle qui reprend un `id` intégré le **remplace** — de quoi dégrader un
sink que l'équipe a délibérément accepté, sans patcher Thot. Un fichier mal
formé arrête l'audit en nommant le fichier et la clé fautive, plutôt que de
laisser croire à une absence de finding.

### Les suppressions

Une suppression est la seule affirmation sur la sécurité qu'aucun outil ne
relit — y compris celui-ci, par construction. `# nosec`, `# noqa: S310`,
`// eslint-disable … security/…` : c'est une affirmation sur le code, écrite
une fois, qui survit aux appelants qu'elle décrivait.

Deux fois dans un même audit, ici, elle était fausse :

| suppression | ce qu'elle affirmait | ce qui était vrai |
|---|---|---|
| `# nosec B310 — scheme checked above` | le schéma est contrôlé | il arrêtait `file://` et rien d'autre — SSRF vers le service de métadonnées |
| `# noqa: S310 (configured peers)` | l'URL vient de la configuration | un des appelants la lit dans un argument d'outil, donc du modèle |

Thot les rapporte donc **comme classe**, en LOW, avec le motif écrit à côté.
Le finding ne dit pas « cette ligne est dangereuse » : il dit « personne n'a
relu la raison pour laquelle elle a été excusée ». Sur une passe `--deep`,
c'est un agent qui va vérifier si le motif tient encore.

Pour Python, ce sont les vrais jetons de commentaire qui sont lus, pas des
motifs — une expression rationnelle ne distingue pas `# nosec` dans un
commentaire du même texte cité dans une docstring, et la docstring de ce
module en cite deux.

Une suppression posée sur une ligne que **cet audit signale** n'est pas le
même objet : c'est une affirmation qui contredit un finding vivant, écrite
par quelqu'un qui a lu la même ligne et conclu autrement. Elle est remontée
d'un cran et le dit. Mesuré sur Hermes : **7 sur 45** — et trois des
suppressions lues ce jour-là étaient fausses.

Mesuré : **0 sur Thot, 0 sur Prime, 45 sur Hermes.**

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

### Quel paramètre l'argument remplit

Un helper dont *un* paramètre atteint un sink ne rend pas dangereux tout ce
qu'on lui passe. Le moteur appariait pourtant l'appelant avec l'ensemble des
sinks du callee, sans regarder où l'argument atterrissait :

```python
def helper(safe, cmd):
    os.system(cmd)          # seul `cmd` atteint le shell

helper(sys.argv[1], "ls")   # la donnée va dans `safe` — et c'était rapporté
```

La position est maintenant lue au site d'appel, et le nom pour un argument
nommé. C'est ce que le moteur JavaScript faisait déjà de son côté.

Mesuré, une fois l'exécution possible : sur 83 238 résolutions demandées en
analysant Thot et `hermes/tools`, 90 % désignent un paramètre unique et 9,8 %
n'en désignent aucun ; 0,1 % restent ouvertes (`f(*rest)`, `f(**options)`) et
gardent la réponse large. Le callee offrait 2,68 paramètres en moyenne, donc
près des deux tiers de l'espace de recherche disparaissent — l'analyse de
`hermes/tools` passe de 11,4 s à 9,5 s.

Sur le nombre de findings, en revanche : **aucun changement**. Thot, `prime` et
`hermes/tools` rendent exactement les mêmes 151 candidats avant et après, dont
zéro inventé — la propriété de sûreté tient sur le terrain. Quatre chemins de
teinte se raccourcissent, rien de plus. La forme corrigée ci-dessus est réelle
et le test le prouve, mais elle ne se produit dans aucun des trois arbres
mesurés : ce correctif achète de la vitesse et des chemins plus justes, pas
moins de bruit.

Deux formes ne disent rien : `helper(*args)` étale un nombre inconnu de
valeurs, et `helper(**options)` n'en nomme aucune. Là, le moteur garde la
réponse large qu'il donnait avant — l'ensemble retenu est toujours **inclus**
dans celui d'avant, donc affiner ne peut que retirer un finding, jamais en
inventer un.

Le receveur est sauté sur la foi de la signature du callee, pas de la syntaxe
de l'appel : `Runner().go(x)` se rend en un `go` sans point, et `Cls.m(obj, x)`
comme `obj.m(x)` sont tous deux un attribut. Une méthode étant presque toujours
appelée liée, c'est `self` en tête des paramètres qui décide — l'appel non lié
est la seule forme lue un cran trop court.

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

La teinte **à travers les fichiers** est réservée à Python : JavaScript et
TypeScript sont indexés, suivis dans un corps de fonction et jusqu'à un
helper du même fichier, et s'arrêtent là faute de graphe d'appels résolu — le
tableau plus haut le dit ligne par ligne. Les règles par motif, elles,
s'appliquent partout.

Sans `--deep`, chaque finding est `PLAUSIBLE` : détecté statiquement, pas
encore prouvé par exécution. Avec `--deep`, un finding `confirmed` a survécu
à une réfutation adverse — ce n'est pas encore une preuve d'exécution, qui
viendra avec le repro. Et l'absence de finding n'est pas une preuve d'absence
de défaut : dispatch dynamique, réflexion et métaprogrammation échappent à
l'analyse.

La recherche plein texte dans les sessions cesse d'être à coût constant sur
les SQLite dont fts5 ne sait pas remonter les rowid : le moteur y trie
l'ensemble des correspondances au lieu de couper à vingt. Mesuré sur celui
qu'embarque CPython 3.12 — 6 588 instructions contre 27 443 quand le corpus
est multiplié par cinq, là où un moteur capable reste à 2 215 puis 2 698. Un
test le vérifie et nomme la version quand elle ne le permet pas.

## Développement

```bash
cd Thot
uv run pytest -q
```

Installé en éditable : le code source fait foi immédiatement. En revanche, si
`pyproject.toml` change (nouvelle dépendance), il faut relancer
`uv tool install --editable --from . thot --force`.

Le noyau déterministe (`codemap`, `taint`, `scope`, `scoring`, `store`,
`report`) ne dépend d'aucun agent et ne touche pas au réseau — un test le
vérifie et fait échouer la suite si ça change.

Spec et plans : `docs/superpowers/`.
