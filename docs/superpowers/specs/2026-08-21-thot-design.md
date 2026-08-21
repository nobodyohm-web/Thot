# Thot — Design

**Date :** 2026-08-21
**Statut :** approuvé, prêt pour le plan d'implémentation
**Auteur :** nobodyohm-web (conception assistée)

---

## 1. Problème

Les outils d'audit de code existants se répartissent en deux familles, également décevantes :

- **Les scanners statiques** (Semgrep, Bandit, CodeQL) produisent beaucoup de bruit. Ils
  ignorent l'accessibilité réelle du code fautif, ne prouvent rien, et ne corrigent rien.
  Leur taux de faux positifs impose un travail de tri qui coûte plus cher que ce qu'ils
  font gagner.
- **Les agents LLM généralistes** avalent un repo, produisent une liste plausible, et
  n'ont aucun moyen de distinguer ce qu'ils ont compris de ce qu'ils ont halluciné. Le
  coût en tokens croît avec la taille du repo, la qualité décroît avec elle.

Thot vise le point que ni l'un ni l'autre n'atteint : **un audit dont chaque conclusion
est prouvée, dont chaque correction est testée, et dont le coût ne croît pas avec la
taille du dépôt.**

## 2. Objectifs

1. Analyser un dépôt entier en profondeur — plusieurs centaines de milliers de lignes —
   sans que le coût en tokens croisse proportionnellement.
2. Ne rapporter que des défauts **vérifiés** : chaque finding porte un scénario de
   défaillance concret, et si possible un test exécutable qui échoue.
3. Proposer des corrections **testées** : patch minimal dans un worktree isolé, suite de
   tests du projet au vert, repro passé au vert, aucune régression.
4. Produire un livrable de qualité professionnelle : rapport lisible, export SARIF,
   provenance complète.
5. Se mesurer lui-même : taux de détection et taux de faux positifs publiés à chaque
   version, sur un corpus à vérité connue.
6. Fonctionner dans le terminal, comme outil de travail quotidien.

## 3. Non-objectifs

- **Pas un IDE, pas un assistant de développement.** Thot audite et durcit ; il ne code
  pas de fonctionnalités.
- **Pas de pentest de cibles distantes.** Le périmètre est le code source local, et
  l'exécution de repros dans un sandbox local. Aucune capacité d'attaque réseau.
- **Pas un remplaçant des linters.** Le style, le formatage et les conventions restent
  chez les outils qui les font bien. Thot cible les défauts qui ont des conséquences.
- **Pas de support universel des langages en v1.** Python et TypeScript/JavaScript
  d'abord ; l'architecture reste ouverte, l'implémentation ne s'éparpille pas.

## 4. Principes directeurs

Ces cinq règles tranchent tous les arbitrages ultérieurs.

1. **Le déterministe d'abord, le modèle en juge.** Un LLM ne scanne jamais. Les
   détecteurs AST et la propagation de teinte produisent des *candidats* ; le modèle
   tranche uniquement l'exploitabilité et la sévérité de cas déjà cadrés.
2. **Rien ne sort sans preuve.** Un finding sans scénario de défaillance reproductible
   est au mieux `PLAUSIBLE`, et rapporté séparément des `CONFIRMED`.
3. **L'état lourd reste hors du contexte.** AST, graphes et index vivent dans des
   variables Python et une base SQLite, jamais dans la fenêtre du modèle.
4. **Le noyau ne dépend de personne.** Ni de Prime Agent, ni d'Hermes. Ce sont des
   moteurs interchangeables derrière un port.
5. **Ce qui a déjà été jugé ne remonte plus.** Les verdicts sont persistés et versionnés.
   La valeur de l'outil se compose dans le temps.

## 5. Architecture

### 5.1 Vue d'ensemble

```
                    ┌─────────────────────────────┐
                    │      NOYAU (Python pur)     │
                    │  scope · map · taint        │
                    │  select · probe · refute    │
                    │  prove · patch · report     │
                    │  store                      │
                    └──────────┬──────────────────┘
                               │
                    ┌──────────▼──────────┐
                    │   engine/ (PORT)    │
                    └──┬───────┬───────┬──┘
                       │       │       │
              ┌────────▼─┐ ┌───▼────┐ ┌▼──────────┐
              │  Prime   │ │ Hermes │ │  Direct   │
              │  rlm()   │ │delegate│ │  API      │
              └──────────┘ └────────┘ └───────────┘
```

### 5.2 Le port `Engine`

Pièce maîtresse : le noyau ne sait pas qui exécute les agents.

```python
class Engine(Protocol):
    async def run(self, task: AgentTask) -> AgentResult: ...
    async def fan_out(self, tasks: list[AgentTask]) -> list[AgentResult]: ...
    @property
    def capabilities(self) -> EngineCapabilities: ...
```

| Implémentation | Mécanisme | Quand elle est choisie |
|---|---|---|
| `PrimeEngine` | `rlm(...)` dans le kernel IPython | défaut — parallélisme natif, état persistant hors contexte |
| `HermesEngine` | `delegate_tool` / subagents Hermes | quand Thot tourne sous Hermes (cron, gateway) |
| `DirectEngine` | appel API/OAuth direct | CI, machine nue, ou secours |

`EngineCapabilities` déclare ce que le moteur sait faire (parallélisme maximum, accès
au kernel, tiering de modèles disponible). Le noyau adapte sa stratégie sans jamais
connaître l'implémentation.

**Tests de contrat :** une suite unique s'exécute contre les trois implémentations. Un
moteur qui la passe est interchangeable, par construction.

### 5.3 Répartition des responsabilités

Aucune ligne de ce tableau n'est implémentée deux fois.

| Besoin | Porté par | Justification |
|---|---|---|
| Exécution parallèle d'agents d'analyse | Prime `rlm()` | subagents natifs à contexte isolé |
| État lourd hors contexte | Prime kernel IPython | variables Python persistantes |
| Mémoire des findings entre audits | Hermes | mémoire persistante existante |
| Planification (nocturne, sur push) | Hermes cron | déjà robuste |
| Rapport poussé (Telegram, mail, kanban) | Hermes gateway | déjà multi-plateforme |
| Continuité malgré un quota épuisé | Hermes fallback providers | déjà implémenté |
| Sandbox d'exécution des repros | Hermes environments (docker/local) | `tools/environments/docker.py` |
| Audit supply-chain (OSV) | Hermes `security` | déjà là |
| Détection de la recipe run/test | Hermes `verify` | déjà là |
| **Méthodologie d'audit** | **Thot seul** | c'est sa raison d'être |

## 6. Le pipeline

Neuf phases (0 à 8). Les phases 0, 1 et 2 ne consomment aucun token de modèle ; la
phase 6 n'en consomme que pour générer le repro.

### Phase 0 — Scope

**Entrée :** un chemin de dépôt.
**Sortie :** un `ScopeManifest`.

Détection des langages, de la recipe de build et de test (déléguée à `hermes verify`
quand disponible, sinon heuristiques propres), des points d'entrée (`main`, routes HTTP,
handlers CLI, tâches cron, endpoints exposés), et lecture du fichier d'autorisation.

**Garde-fou :** l'audit refuse de démarrer sans `.thot/authorization.yaml` déclarant que
l'opérateur est propriétaire du code ou mandaté pour l'auditer. Voir §11.

### Phase 1 — Carte *(coût LLM : nul)*

**Entrée :** `ScopeManifest`.
**Sortie :** `CodeGraph` en mémoire + persisté dans SQLite.

- Parsing AST : `ast` de la stdlib pour Python (précision maximale), `tree-sitter` pour
  les autres langages (socle uniforme).
- Graphe d'imports et graphe d'appels (résolution statique, best-effort sur les appels
  dynamiques — les limites sont documentées, pas masquées).
- Inventaire des **sinks** : `subprocess`, `eval`/`exec`, requêtes SQL concaténées,
  désérialisation (`pickle`, `yaml.load`, `JSON.parse` sur entrée non validée), écriture
  FS, requêtes réseau, primitives crypto, comparaisons de secrets.
- Inventaire des **sources** : arguments CLI, corps et paramètres de requêtes HTTP,
  variables d'environnement, fichiers lus, messages entrants, retours d'API tierces.
- Churn git par fichier et par symbole (un défaut dans du code très modifié est plus
  probable et plus coûteux).
- Dépendances et vulnérabilités connues (délégué à `hermes security` / OSV.dev).

### Phase 2 — Taint *(coût LLM : nul)*

Propagation source → sink. Intra-procédurale complète, inter-procédurale sur le graphe
d'appels avec une profondeur bornée (défaut : 3 sauts). Chaque chemin complet devient un
**candidat**, avec sa chaîne `CodeRef` intégrale.

C'est ce qui distingue Thot d'un grep amélioré, et c'est ce qui permet aux phases LLM de
ne travailler que sur des cas déjà cadrés.

**Limite assumée :** l'analyse est incomplète par construction (dispatch dynamique,
réflexion, métaprogrammation). Elle produit des faux négatifs, jamais des faux positifs
silencieux — un chemin rapporté est un chemin réellement présent dans le graphe.

### Phase 3 — Ciblage *(coût LLM : bas, tier économique)*

On n'audite pas uniformément. Les zones sont classées par **risque porté** :

```
risque = accessibilité(graphe) × densité_de_sinks × churn × sensibilité(domaine)
```

où `sensibilité` majore l'authentification, l'autorisation, la cryptographie, le parsing
d'entrées non fiables et la gestion des secrets. Le budget d'audit est alloué du haut de
ce classement vers le bas jusqu'à épuisement.

### Phase 4 — Analyse *(coût LLM : moyen, parallèle)*

Un agent par zone, via `Engine.fan_out()`. Chaque agent reçoit **uniquement les slices de
code de sa zone** — jamais le dépôt, jamais le graphe complet — plus les candidats de
teinte qui la traversent.

Sortie contrainte par schéma : une liste de `Finding` en état `PLAUSIBLE`. Un agent qui
ne trouve rien retourne une liste vide, ce qui est un résultat valide et attendu.

### Phase 5 — Réfutation *(coût LLM : haut, strictement ciblé)*

Chaque finding est soumis à N réfuteurs (défaut : 3) à **lentilles distinctes** :

| Lentille | Question posée |
|---|---|
| Garde en amont | Une validation, un type, un contrat rend-il ce chemin impossible ? |
| Accessibilité | Ce code est-il atteignable depuis un point d'entrée réel ? |
| Reproductibilité | Peut-on écrire des entrées concrètes qui déclenchent le défaut ? |

Les réfuteurs sont explicitement instruits de **tuer** le finding et de conclure à la
réfutation en cas de doute. Un finding survit à la majorité. Les findings de sévérité
haute reçoivent en plus un **second avis d'une autre famille de modèles** (via le
multi-provider d'Hermes) : trois instances du même modèle partagent leurs angles morts.

### Phase 6 — Preuve *(coût LLM : quasi nul)*

Pour chaque survivant, génération d'un repro exécutable — un test qui échoue sur le code
actuel — lancé dans le sandbox. Résultat :

- Repro rouge sur le code actuel → `CONFIRMED`.
- Pas de repro possible (défaut de conception, faiblesse crypto, condition de course non
  déterministe) → `PLAUSIBLE`, rapporté dans une section distincte, jamais mélangé.

### Phase 7 — Remédiation *(coût LLM : moyen)*

Dans un worktree git isolé, jamais dans l'arbre de travail de l'opérateur :

1. Patch minimal — la correction la plus petite qui neutralise le chemin, pas une
   réécriture.
2. Le repro doit passer au vert.
3. La suite de tests du projet doit rester au vert (comparaison avant/après, pas
   « ça passe » dans l'absolu).
4. Aucun nouveau finding introduit par le patch — re-passage des détecteurs sur le diff.

Un patch qui échoue à l'une de ces conditions est rapporté comme tentative échouée, avec
la raison. Il n'est jamais présenté comme une correction.

### Phase 8 — Rapport et mémoire *(coût LLM : bas)*

Rapport Markdown et HTML, export JSON et SARIF 2.1.0, classement par
`sévérité × confiance`. Persistance des findings, des verdicts et de la provenance.

## 7. Contrats de données

```python
@dataclass(frozen=True)
class Finding:
    id: str                    # hash stable : (règle, fichier, symbole normalisé)
    rule: str                  # ex. "taint.subprocess.shell"
    severity: Severity         # calculée (§8), jamais opinée
    confidence: Confidence     # CONFIRMED | PLAUSIBLE | REFUTED
    location: CodeRef          # fichier:ligne, symbole, hash AST
    taint_path: list[CodeRef]  # source → … → sink
    failure_scenario: str      # entrées concrètes → comportement fautif
    repro: Repro | None        # test exécutable, rouge avant patch
    patch: Patch | None        # diff + résultats de tests avant/après
    provenance: Provenance     # commit, modèles, prompts, votes des réfuteurs
```

Le contrat est versionné (`schema_version`). Toute évolution incompatible incrémente la
version et fournit une migration du store.

## 8. Sévérité calculée

```
sévérité = impact × accessibilité × confiance
```

- **impact** — dérivé de la classe du sink (exécution de code > injection SQL > écriture
  FS arbitraire > divulgation d'information).
- **accessibilité** — issue du **graphe d'appels**, pas d'une opinion : distance au point
  d'entrée public le plus proche. Un défaut inatteignable depuis l'extérieur est
  automatiquement dégradé.
- **confiance** — vote des réfuteurs et présence d'un repro.

C'est le mécanisme anti-faux-positifs le plus rentable : dans la pratique, une large part
des « critiques » des scanners classiques vit dans du code mort ou strictement interne.

## 9. Économie de tokens

Quatre mécanismes, par ordre d'impact décroissant.

1. **Le déterministe fait le volume.** Phases 0, 1 et 2 : aucun appel modèle ; phase 6
   marginale (génération du repro), le reste étant de l'exécution. Sur un
   dépôt de 200 000 lignes, l'essentiel du travail d'analyse est du calcul, pas de
   l'inférence.
2. **Cache par hash de fonction.** Chaque symbole analysé est stocké avec le hash de son
   AST normalisé — insensible au formatage, aux commentaires et aux renommages de
   variables locales. Un symbole inchangé n'est jamais réanalysé.
3. **Mode incrémental.** Par défaut, un ré-audit ne traite que le diff depuis le dernier
   commit audité, plus les symboles dont le graphe d'appels a changé. Le premier audit
   d'un dépôt est coûteux ; les suivants sont marginaux. C'est ce qui rend un audit
   quotidien viable.
4. **Tiering de modèles.** Le mécanique (inventaire, normalisation, extraction) sur le
   tier économique ; le jugement (exploitabilité, sévérité, conception du patch) sur le
   tier fort. Le second avis cross-modèle est réservé aux sévérités hautes.

**Plafond de coût.** Chaque run accepte un budget (tokens ou euros). À l'épuisement,
Thot s'arrête proprement et produit un rapport partiel explicitement marqué comme tel,
avec la liste de ce qui n'a pas été couvert. Une couverture tronquée silencieuse serait
un mensonge par omission.

## 10. Persistance

- **`~/.thot/store.db`** (SQLite) — findings, verdicts, provenance, cache d'analyse,
  historique des runs. Local, volumineux, jamais versionné.
- **`.thot/verdicts.yaml`** — dans le dépôt audité, donc versionné et relu en PR :
  verdicts humains (`accepted`, `false_positive`, `wontfix`) avec justification
  obligatoire et hash du finding. Un verdict lié à un hash de symbole devient caduc si le
  symbole change — le finding revient légitimement.
- **`.thot/authorization.yaml`** — déclaration de périmètre et d'autorisation (§11).

## 11. Sécurité et éthique

- **Autorisation explicite.** Pas d'audit sans `.thot/authorization.yaml` déclarant le
  propriétaire du code et la portée. C'est une friction volontaire.
- **Périmètre local.** Thot lit du code source et exécute des repros dans un sandbox
  local. Aucune capacité d'attaque réseau, aucune cible distante, aucun scan externe.
- **Exécution sandboxée.** Les repros s'exécutent dans un conteneur (via les
  environnements Hermes) ou, à défaut, dans un sous-processus isolé avec système de
  fichiers temporaire, réseau coupé et timeout strict. Le code d'un dépôt audité est
  traité comme non fiable.
- **Secrets.** Les secrets détectés sont rapportés par emplacement et par type, jamais
  par valeur. Aucune valeur de secret n'entre dans un prompt, un log ou un rapport.
- **Contenu non fiable.** Le code source audité est de la donnée, jamais une instruction.
  Les prompts des agents d'analyse isolent explicitement le code examiné des consignes.

## 12. Auto-évaluation

Un harnais d'évaluation, exécuté à chaque version, sur un corpus à vérité connue :

- **Bugs injectés** par mutation contrôlée dans des dépôts propres (vérité parfaitement
  connue, volume illimité).
- **CVE réelles** sur des dépôts publics, au commit précédant le correctif (vérité
  réaliste, volume limité).

Deux métriques publiées et suivies dans le temps : **taux de détection** et **taux de
faux positifs**. Une régression sur l'une des deux bloque la release.

Sans cette section, personne — à commencer par l'opérateur — ne peut savoir si l'outil
est bon. C'est ce qui sépare un instrument d'un jouet, et c'est ce qui rend un audit
défendable devant un tiers.

## 13. Adaptateurs et interfaces

- **CLI** (`thot`) — interface principale. `thot audit <path>`, `thot report`,
  `thot verdict <id> <status>`, `thot eval`.
- **Skill Prime Agent** — package Python importable dans le kernel. Le modèle pilote
  Thot par le code (`import thot`), et `PrimeEngine` utilise `rlm()` pour le fan-out.
- **Plugin Hermes** — déclenchement par cron, mémoire des findings, envoi des rapports
  sur les plateformes configurées, `HermesEngine` pour le fan-out.

Les adaptateurs sont **minces** : traduction et câblage uniquement. Aucune logique
d'audit n'y vit. Chacun est couvert par les tests de contrat du port.

## 14. Stack

- Python 3.11+, `uv` pour l'environnement et le packaging.
- `tree-sitter` (multi-langage), `ast` stdlib (Python), `sqlite3` stdlib.
- `pytest` pour les tests, développement en TDD.
- Aucune dépendance à Prime Agent ou Hermes dans le noyau — vérifié par un test
  d'import qui échoue si l'un d'eux apparaît dans les dépendances de `thot.core`.

## 15. Jalons

Chaque jalon livre quelque chose d'utilisable seul.

| Jalon | Contenu | Utilisable pour |
|---|---|---|
| **M1** | `scope` + `map` + `store` + CLI, sortie JSON, zéro LLM | inventaire et cartographie déterministes d'un dépôt |
| **M2** | `taint` + candidats | détection de chemins source→sink sans aucun modèle |
| **M3** | port `Engine` + `DirectEngine` + `probe` + rapport Markdown | premier audit assisté par modèle, de bout en bout |
| **M4** | `refute` + sévérité calculée + SARIF + `verdicts.yaml` | audit crédible, faux positifs sous contrôle |
| **M5** | `prove` + `patch` (worktree, tests) | findings prouvés et corrections testées |
| **M6** | `PrimeEngine` + cache + mode incrémental | passage à l'échelle, coût marginal des ré-audits |
| **M7** | `HermesEngine` + plugin (cron, notifications, mémoire) | audits planifiés et rapports poussés |
| **M8** | harnais d'auto-évaluation + métriques publiées | preuve chiffrée de la qualité de l'outil |

## 16. Risques

| Risque | Portée | Mitigation |
|---|---|---|
| Le graphe d'appels rate le dispatch dynamique | faux négatifs sur code très dynamique | limites documentées ; les points d'entrée dynamiques connus sont déclarables dans le scope |
| Coût du premier audit d'un gros dépôt | frein à l'adoption | budget obligatoire, ciblage par risque, rapport partiel honnête |
| Les API internes de Prime et Hermes évoluent | adaptateurs cassés | le port isole le noyau ; tests de contrat exécutés contre les trois moteurs |
| Corpus d'évaluation trop petit | métriques peu fiables | mutation contrôlée pour le volume, CVE réelles pour le réalisme |
| Sur-confiance dans les patchs générés | régression introduite | quatre conditions cumulatives (§ phase 7) ; un patch douteux est rapporté comme échec |

## 17. Décisions ouvertes

Aucune ne bloque le démarrage de M1.

- Support d'un troisième langage (Go ? Rust ?) — à trancher après M4, sur usage réel.
- Format du rapport HTML : page autonome ou artifact publié — à trancher à M4.
- Seuil exact de profondeur inter-procédurale (défaut 3) — à calibrer sur le corpus d'évaluation à M8.
