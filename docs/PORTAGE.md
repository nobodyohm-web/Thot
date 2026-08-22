# Ce qui vient d'où

Thot est né de deux programmes. Ce document dit, fichier par fichier, ce qui
en est venu et sous quel nom — parce que les noms ont changé, et qu'un
`ls` côte à côte ne montre donc rien.

Vérifiable : chaque ligne de la colonne « Thot » existe dans `src/`.

Trois provenances sont distinguées, parce qu'elles ne valent pas la même chose :

| | |
|---|---|
| **copié** | le fichier est celui d'amont, parfois avec des modifications nommées |
| **porté** | la conception est d'amont, le code est celui de Thot |
| **repris** | un format que les deux lisent, inventé par ni l'un ni l'autre |

---

## Hermes Agent → Thot

### L'état des sessions — les `hermes_state*.py`

C'est le bloc que l'on cherche en premier et que l'on ne trouve pas, parce que
les cinq fichiers sont devenus un paquet.

| Hermes | Thot | |
|---|---|---|
| `hermes_state.py` (13 114 l.) | `state/store.py` | porté |
| `hermes_state_search.py` (2 493 l.) | `state/search.py` | porté |
| `hermes_state_schema.py` (1 340 l.) | `state/schema.py` | porté |
| `hermes_state_portability.py` (714 l.) | `state/portability.py` | porté |
| `hermes_state_common.py` (690 l.) | fondu dans `state/schema.py` | porté |

**16 351 lignes → ~900.** Ce qui est gardé est ce que la production a payé :
schéma additif, miroir FTS entretenu par déclencheur, FTS5 *sondé* et non
supposé, WAL avec repli silencieux, chaînes de compression par `parent_id`,
imports qui renumérotent au lieu d'écraser, et — le défaut qui compte le plus
dans `hermes_state_search.py` — une requête d'utilisateur mise entre guillemets
avant d'atteindre `MATCH`, sans quoi `run_command(` fait lever FTS5 et
l'exception se lit comme « aucun résultat ».

Ce qui est jeté est tout ce qu'exige une passerelle multi-plateformes et pas un
outil d'audit local : extension CJK, registre de réparation inter-processus,
barrières de checkpoint macOS, verrous de compression, quarantaine de bases
zéro-remplies.

### Le reste d'Hermes

| Hermes | Thot | |
|---|---|---|
| `skills/` (82) + `optional-skills/` (117) | `skills/` (90) + `optional-skills/` (117) | copié |
| `tools/skills_guard.py` (1 174 l.) | `guard/skill_guard.py` | copié |
| `plugins/security-guidance/patterns.py` | `guard/patterns.py` | copié |
| `optional-mcps/` (20 manifestes) | `mcp-catalog/` + `mcp/catalog.py` | copié |
| `hermes_cli/security_audit.py` | `supply/osv.py`, `supply/discover.py`, `supply/audit.py` | porté |
| `tools/osv_check.py` | `supply/osv.py` (cache), `cli.py::_mcp_check` | porté |
| `tools/environments/docker.py` (2 050 l.) | `sandbox/docker.py` | porté |
| `tools/environments/local.py` | `sandbox/local.py` | porté |
| `trajectory_compressor.py` (1 598 l.) | `state/compaction.py` | porté |
| `hermes_cli/plugins.py` | `plugins/loader.py`, `plugins/notify.py` | porté |
| `plugins/memory/*` (8 fournisseurs) | `memory/factory.py`, `layered.py`, `remote.py`, `jsonfile.py` | porté |
| `agent/memory_provider.py` | `memory/base.py` | porté |
| `gateway/` + `plugins/platforms/*` (22) | `gateway/` (5 canaux) | porté |
| `cron/jobs.py` | `schedule/jobs.py`, `runner.py`, `install.py` | porté |
| `hermes_constants.py::get_hermes_home` | `paths.py` | porté |
| `hermes_logging.py` (800 l.) | `logs.py` | porté |
| `hermes_bootstrap.py` (239 l.) | `bootstrap.py` | porté |
| `toolsets.py` (1 083 l.) | `toolsets.py` | porté |
| `plugins/observability/*` | `plugins/audit-log/` | porté |

### Ce qui n'est pas porté, et pourquoi

Hermes contient **4 457 fichiers Python**. Thot en a 98. L'écart n'est pas un
retard, c'est le sujet : Hermes est un assistant généraliste avec qui on vit,
Thot audite du code.

Ne sont pas portés, par catégorie :

- **`cli.py` (21 445 l.) et `run_agent.py` (9 181 l.)** — le CLI et la boucle
  d'agent d'Hermes. Thot a les siens ; les copier reviendrait à installer
  Hermes.
- **navigateur, GUI, média** (~40 fichiers dans `tools/`, 7 dans `agent/`) —
  `browser_camofox`, `computer_use`, `image_gen`, TTS, mixage vocal. Un
  auditeur de code n'en a aucun usage.
- **facturation et identité fournisseur** (~23 fichiers dans `agent/`) —
  crédits, quotas, adaptateurs Bedrock/Azure/Copilot, pools de credentials.
  Thot délègue l'inférence au CLI officiel, précisément pour ne pas détenir
  ça.
- **harnais RL et évaluation** — `batch_runner.py`, `mini_swe_runner.py`,
  `evals/`. Hors sujet.
- **`mcp_serve.py`** — doublé par `mcp_server.py`, écrit pour les besoins de
  Thot (lecture seule, six outils).
- **plomberie du runtime** — `registration_lifecycle.py`, `utils.py`,
  `hermes_time.py`, `model_tools.py`, `agent/` pour l'essentiel.
- **les 10 autres environnements** de `tools/environments/` — Modal, Daytona,
  Vercel, Singularity, SSH. Ils donnent *plus* de machine à un assistant ;
  Thot en veut moins.
- **les 17 autres canaux** de `plugins/platforms/` — Feishu, WeCom, Matrix,
  IRC, LINE… Les cinq portés couvrent le cas « préviens-moi » ; les autres
  s'ajoutent en écrivant un objet à deux méthodes (`gateway/base.py`).

---

## Prime Agent → Thot

Prime est en TypeScript : **rien n'est copié**, tout est traduit.

| Prime | Thot | |
|---|---|---|
| `core/goals.ts` | `state/goals.py` | porté |
| `core/prompt-templates.ts` | `commands/loader.py` + `commands/` | porté |
| `core/tools/truncate.ts` | `output.py` | porté |
| `core/usage.ts`, `core/session-stats.ts` | `state/usage.py` | porté |
| `core/context-tree.ts` | `state/usage.py::context_breakdown` | porté |
| `core/export-html/` | `report/html_report.py` | porté |
| `core/compaction/` | `state/compaction.py` (avec Hermes) | porté |
| `skills/skill-creator/` | `skills/software-development/skill-creator/` | porté |
| `core/kernel/`, `tools/ipython.ts` | `kernel/worker.py`, `client.py`, `protocol.py`, `api.py` | porté |
| `prime-agent-runtime/src/rlm/__init__.py` | `kernel/worker.py::rlm`, `client.py::_rlm` | porté |
| `prime-agent-runtime/src/rlm/harness.py` | `harness.py` | porté |
| format `SKILL.md` | `skills/loader.py` | repris |

### Ce qui n'est pas porté de Prime

456 fichiers TypeScript, dont :

- **118 pour l'interface terminal** (`modes/interactive/`) et **32 pour la TUI** —
  Thot a la sienne, en `rich`, dans `ui/theme.py` et `console.py`.
- **25 pour le démon** (`modes/daemon/`) — supervision, leases de session,
  journaux de reprise, familles d'agents. Thot n'a pas de démon d'agents ;
  son `thot serve` est une boucle de 120 lignes qui écoute cinq canaux.
- **`ipykernel` et le protocole Jupyter** — Prime parle à un vrai noyau
  IPython sur ZeroMQ. Thot a porté l'idée (un espace de noms qui survit)
  sans la dépendance : trois verbes sur un tuyau, et le noyau tourne dans
  le conteneur quand un bac à sable est configuré.
- **`agent-messages`, `agent-observe`, familles d'agents** — la
  supervision de sous-agents par le démon. `rlm()` couvre la délégation ;
  l'arbre de familles suppose un démon que Thot n'a pas.
- **ACP, RPC, modes agents-view** — protocoles d'intégration éditeur.

---

## Vérifier soi-même

```bash
ls src/thot/state/          # search.py, store.py, schema.py, portability.py
thot search <mots>          # FTS5, la fonction de hermes_state_search.py
thot skills scan <dossier>  # tools/skills_guard.py
thot deps --list            # hermes_cli/security_audit.py
thot sandbox show pytest    # tools/environments/docker.py
thot gateway list           # gateway/ + plugins/platforms/
thot mcp list               # optional-mcps/
```

## Divergences assumées

Les arbres `hermes/` et `prime/` sont importés verbatim, à une exception près,
et les bibliothèques `skills/` et `optional-skills/` portées depuis Hermes
s'en écartent sur le même fichier :

| fichier | pourquoi |
|---|---|
| `optional-skills/mcp/fastmcp/templates/database_server.py` | injection SQL confirmée par la passe adverse : `f"SELECT * FROM ({sql}) LIMIT {n}"` — la charge `select id from users) --` ferme la sous-requête et commente le `LIMIT`, mesuré 300 lignes au lieu de 50. Le plafond est appliqué par `fetchmany` et non écrit dans le SQL. |
| `hermes/plugins/platforms/a2a/tools.py` | SSRF pilotée par le **modèle**. `a2a_discover` prend son URL dans un argument d'outil (`args.get("url")`) et la passe à `_http_get_json`, dont le `# noqa: S310 (configured peers)` ne couvre pas ce chemin : le corps de la réponse est résumé dans le contexte du modèle. L'URL est validée avant la requête, et les deux aides HTTP contrôlent chaque redirection. |
| `hermes/plugins/platforms/a2a/security.py` | SSRF confirmée par le panel dans un garde qui existait déjà. `is_safe_callback_url` vérifiait une liste de préfixes et une adresse littérale, puis laissait passer tout nom d'hôte : `except ValueError: pass  # not an IP, it's a hostname — fine`. Sa docstring promettait de bloquer les adresses internes ; un nom que l'appelant contrôle répond `127.0.0.1` aussi facilement qu'une adresse publique. Le nom est désormais résolu, **toutes** ses réponses vérifiées, et un nom qui ne résout pas est refusé. |
| `hermes/cron/monitor.py` | SSRF confirmée par le panel, avec renvoi de la réponse. Le contrôle de schéma arrêtait `file://` et rien d'autre ; `monitor_url` est réglable via un **outil d'agent** (`tools/cronjob_tools.py:1809`), donc un modèle soumis à une injection pointait `169.254.169.254` et le corps revenait dans son propre prompt. Le nom est résolu et les adresses privées, loopback, link-local et réservées sont refusées — à chaque saut de redirection, parce qu'un hôte hostile répond publiquement puis redirige vers 127.0.0.1. |
| `hermes/optional-skills/mcp/fastmcp/templates/database_server.py` | **même correctif.** La copie de Hermes avait d'abord été laissée intacte — elle lui appartient. Le panel l'a confirmée une seconde fois, sur cette copie précise, avec la charge `select * from users) LIMIT 999999 --` exécutée localement : 500 lignes rendues pour 50 demandées, plafond `MAX_ROWS=200` contourné. Livrer un gabarit dont on sait qu'il est exploitable est pire qu'une divergence documentée. |

Un fichier de gabarit existe pour être copié, donc un défaut dedans se
propage vers du code atteignable. C'est le risque que `Role.EXAMPLE` ne
modélise volontairement pas — il pèse l'accessibilité, pas la propagation.
