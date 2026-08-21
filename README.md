# Thot

Un assistant de code en terminal qui **connaît déjà ton dépôt**.

Un agent conversationnel découvre un projet en ouvrant des fichiers avec le
modèle : lent, partiel, à repayer à chaque session. Thot calcule la même image
par AST et graphe d'appels — complète, instantanée, gratuite — et ne donne au
modèle que ce qui compte.

## Installation

```bash
uv tool install --editable --from /Users/dev/Desktop/Thot thot
```

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

```bash
thot verdicts                    # tout ce qui a été décidé
thot verdicts --path src/auth    # sur un chemin
thot verdicts --forget <id>      # revenir sur une décision
thot audit . --no-memory         # ignorer la mémoire pour ce run
```

La mémoire s'applique **avant** le modèle : un candidat déjà écarté n'est
jamais renvoyé à l'analyse. Un run où tout est écarté ne fait aucun appel.
Et les réfutations de `--deep` s'enregistrent d'elles-mêmes : deux appels
modèle, payés une fois.

Rien n'est jamais supprimé en silence. Un finding écarté reste dans le rapport
en `refuted`, avec sa raison et son auteur — un audit qui cache ce qu'on lui a
dit d'ignorer n'est pas relisable.

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

Ordre de grandeur : 6 924 fichiers (4 457 Python) en ~59 s, 3 findings
au-dessus du seuil.

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
