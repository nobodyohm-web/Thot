---
description: Trier les findings d'un fichier — nommer l'entrée, ou classer sans suite.
argument-hint: <chemin>
---

Applique la méthode `vulnerability-triage` aux findings qui concernent `$1`.

Pour chacun, dans cet ordre :

1. `audit` pour les lister, puis `callers` sur le symbole qui contient le sink.
2. Nomme l'entrée concrète qui atteint ce sink — un argument HTTP, un champ de
   formulaire, une variable d'environnement, un fichier lu. Si tu ne peux pas la
   nommer, ce n'est pas un finding : dis-le et passe au suivant.
3. Écris le scénario d'échec en une phrase, avec la charge utile exacte.

Termine par une liste courte : ce qui est exploitable, ce qui ne l'est pas, et
pourquoi. Ne propose aucune correction avant que j'aie validé le tri.
