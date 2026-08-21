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
| `/audit` | relancer l'analyse et afficher les findings |
| `/scan` | recalculer la carte du dépôt |
| `/model` | changer de modèle |
| `/clear` | oublier la conversation en cours |
| `/quit` | quitter |

### Modèles

| Choix | Ce qu'il faut |
|---|---|
| **Claude** | une clé API Anthropic (`sk-ant-…`) |
| **OpenAI** | une clé API, ou `OPENAI_API_KEY` dans l'environnement |
| **Local** | Ollama ou LM Studio qui tourne — gratuit, hors ligne |
| **Autre** | n'importe quel endpoint compatible OpenAI |

`thot login` pour changer, `thot logout` pour oublier. La configuration vit dans
`~/.thot/config.json`, en `0600`.

**Un abonnement Claude ne fonctionne pas ici.** Anthropic n'accepte les jetons
d'abonnement que depuis ses propres clients ; les faire passer depuis un
programme tiers demanderait d'usurper l'identité de Claude Code, ce que Thot ne
fait pas. Thot détecte l'abonnement uniquement pour te l'expliquer au bon
moment.

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

### Calibration

La précision compte autant que la détection. Sont volontairement **non**
rapportés :

- `subprocess.run(cmd)` sans `shell=True` — aucun shell ne lit la commande.
- `cursor.execute("… ?", params)` — requête littérale, paramètres liés.
- Une valeur passée par `int()`, `shlex.quote()`, `os.path.basename()`,
  `html.escape()` — ces appels cassent la chaîne de contamination.
- Un défaut qu'aucun point d'entrée n'atteint est dégradé automatiquement.
- `payload.get(...)` n'est pas `requests.get(...)`.

Ordre de grandeur : 6 924 fichiers (4 457 Python) en ~59 s, 3 findings
au-dessus du seuil.

## Limites

Python uniquement pour l'analyse. Chaque finding est `PLAUSIBLE` : détecté
statiquement, pas encore prouvé par exécution. L'absence de finding n'est pas
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
