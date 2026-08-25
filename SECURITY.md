# Politique de sécurité

## Signaler une vulnérabilité

Passe par le **signalement privé de GitHub** — onglet *Security*, puis
*Report a vulnerability*. Il est activé sur ce dépôt. N'ouvre pas d'issue
publique pour une faille : une issue est indexée avant d'être lue.

À quoi t'attendre : un accusé de réception sous sept jours, un premier verdict
sous trente. Ce dépôt est un projet personnel sans astreinte ; ces délais
engagent une attention, pas un service.

## Ce que Thot fait délibérément

Trois comportements ressemblent à des failles et n'en sont pas. Ils sont
nommés ici pour qu'un rapport qui les redécouvre n'ait pas à être écrit.

**Le noyau exécute du code arbitraire** (`src/thot/kernel/worker.py`). C'est
sa fonction : une cellule Python dont les variables survivent d'un tour à
l'autre. La garde n'est pas de refuser l'exécution, c'est que le noyau soit
**toujours un sous-processus**, jamais le processus de Thot — un `exec()`
en interne remettrait au code audité les identifiants du modèle et le
registre des verdicts.

**Le bac à sable `local` n'isole rien** (`src/thot/sandbox/local.py`). Son
propre `describe()` le dit : « aucune isolation — la commande tourne sous ton
compte ». C'est le mode par défaut assumé pour un dépôt qu'on a écrit
soi-même ; `--sandbox docker` existe pour tous les autres, avec
`--cap-drop ALL`, `no-new-privileges`, tmpfs nosuid et des limites de
processus, de mémoire et de CPU.

**Les tests contiennent de faux secrets** (`tests/test_guard.py`). Des jetons
AWS et GitHub d'apparence valide, syntaxiquement corrects et rattachés à
aucun compte, servent à vérifier que le détecteur de secrets les voit. Ils ne
sont pas exploitables et leur retrait rendrait le détecteur non testé.

## Ce que Thot signale à tort sur lui-même

Plus rien. L'audit tourne en intégration continue, son rapport est joint à
chaque exécution, et les **quatre** findings qu'il produit sont les trois
comportements délibérés ci-dessus.

Il en restait un cinquième, faux, et cette section le déclarait plutôt que de
le taire : `src/thot/session.py`, `sink.sql` sur `kernel.execute(code)` — un
appel nommé `execute` qui reçoit une chaîne construite, sauf qu'il n'y a pas
de base de données et que c'est le noyau Python qui reçoit une cellule. La
règle passait sa barrière parce que le fichier importe `sqlite3`, et il
l'importe pour huit clauses `except sqlite3.Error`.

Compté sur les trois arbres livrés ici : **98 findings `sink.sql`, 98 sur un
fichier qui écrit du SQL en toutes lettres, et exactement un reposant sur un
import seul** — celui-là. Un import dit qu'une erreur de base de données peut
arriver jusqu'ici ; il ne dit pas que du SQL s'y compose, et seul le second
fait de `execute` un curseur. La liste de pilotes a donc quitté la barrière,
et un test nomme la clause `except` qui la déclenchait.

## Hors périmètre

`hermes/` et `prime/` sont du code tiers redistribué tel quel, décrit dans
[NOTICE.md](NOTICE.md). Une faille qui leur appartient se signale chez eux —
[Hermes Agent](https://github.com/NousResearch/hermes-agent),
[Prime Agent](https://github.com/PrimeIntellect-ai/prime-agent) — pas ici. Dis-le-moi
tout de même si le portage la rend atteignable par un chemin que l'amont n'a
pas.

## Versions

`0.1.0` est la seule version publiée, et la seule corrigée.
