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
thot audit . --json --out rapport.json        # export machine
thot audit . --markdown --out rapport.md      # export lisible
thot audit . --fail-on high                   # code de sortie 1 en CI
```

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
