# Thot

Audit de code adossé à des preuves. Analyse déterministe : aucun appel modèle,
aucun réseau, aucune clé API, aucun coût par exécution.

## Installation

```bash
uv tool install --from /Users/dev/Desktop/Thot thot
```

## Usage

```bash
thot init /chemin/du/repo --owner "Ton Nom"   # autorisation, une fois par dépôt
thot audit /chemin/du/repo                    # rapport dans le terminal
thot audit . --paths                          # avec le chemin de teinte complet
thot audit . --all                            # y compris le bruit de faible sévérité
thot audit . --min-severity high              # seuil d'affichage (défaut : medium)
thot audit . --json --out rapport.json        # export machine
thot audit . --markdown --out rapport.md      # export lisible
thot audit . --fail-on high                   # code de sortie 1 en CI
```

`--fail-on` ignore le seuil d'affichage : un finding sous le seuil fait quand
même échouer la CI si sa sévérité atteint le seuil d'échec.

## Ce qu'il fait aujourd'hui

- Inventaire du dépôt : fichiers, langages, points d'entrée, commande de test.
- Graphe d'appels avec résolution best-effort des noms.
- Propagation de teinte source → sink, sur trois niveaux : assignations dans un
  corps, valeurs de retour contaminées, paramètres qui atteignent un sink.
- Sévérité **calculée** : `impact × accessibilité × confiance`, où
  l'accessibilité vient du graphe — un défaut qu'aucun point d'entrée n'atteint
  est automatiquement dégradé.
- Persistance SQLite des runs, findings et hashes de symboles.

Python uniquement pour l'instant.

### Calibration

La précision compte autant que la détection. Sont volontairement **non**
rapportés :

- `subprocess.run(cmd)` sans `shell=True` — aucun shell ne lit la commande,
  quelle que soit la forme de l'argv.
- `cursor.execute("SELECT ... ?", params)` — requête littérale, paramètres liés.
- Une valeur passée par `int()`, `shlex.quote()`, `os.path.basename()`,
  `html.escape()` et consorts — ces appels cassent la chaîne de contamination.
- Un défaut qu'aucun point d'entrée n'atteint est dégradé automatiquement.
- `payload.get(...)` n'est pas `requests.get(...)` : les motifs qualifiés
  exigent leur chemin de module.

### Ordres de grandeur

Dépôt de 6 924 fichiers (4 457 Python) : ~59 s, 3 findings au-dessus du seuil.

## Ce qu'il ne fait pas encore

Vérification adversariale par agents, preuve par repro exécutable, patchs testés
en worktree isolé, export SARIF, TypeScript, mode incrémental.
Voir `docs/superpowers/specs/` et `docs/superpowers/plans/`.

Chaque finding est marqué `PLAUSIBLE` : détecté par analyse statique, pas encore
prouvé par exécution. L'absence de finding n'est pas une preuve d'absence de
défaut — l'analyse est incomplète par construction (dispatch dynamique,
réflexion, métaprogrammation lui échappent).

## Codes de sortie

| Code | Signification |
|---|---|
| `0` | Rien au-delà du seuil |
| `1` | Findings au-delà du seuil `--fail-on` |
| `2` | Erreur d'usage |
| `3` | Autorisation refusée |

## Autorisation

`thot audit` refuse de démarrer sans `.thot/authorization.yaml` déclarant que le
code t'appartient ou que tu es mandaté pour l'auditer. C'est une friction
volontaire.
