---
description: Comparer l'audit courant à un commit passé et ne montrer que le neuf.
argument-hint: <ref-git>
---

Compare l'état actuel du dépôt à `$1`.

1. `run_command` avec `git diff --name-only $1 -- '*.py'` pour la liste des
   fichiers touchés.
2. `audit` pour les findings actuels.
3. Ne garde que les findings dont le chemin apparaît dans le diff.

Présente le résultat en deux blocs : « apparu depuis $1 » et « déjà là avant ».
Le second bloc ne se lit pas, il se compte : donne juste son total.
