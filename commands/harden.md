---
description: Corriger un finding, avec le test qui prouve qu'il est corrigé.
argument-hint: <n° du finding>
---

Corrige le finding n°$1 de la dernière liste `/audit`.

L'ordre compte :

1. Relis le code avec `read_file` — pas seulement la ligne du sink, la fonction
   entière et ses appelants (`callers`).
2. Écris d'abord un test qui échoue et qui reproduit le scénario d'échec décrit
   dans le finding. Lance-le, montre-moi qu'il échoue.
3. Corrige. Relance le test, montre-moi qu'il passe.
4. Relance la suite complète pour vérifier que rien d'autre n'a cassé.

Si le finding s'avère être un faux positif pendant l'étape 1, arrête-toi et
dis-le : `/verdict $1 refute <raison>` sera la bonne suite, pas un correctif.
