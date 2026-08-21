---
name: skill-creator
description: Écrire, valider et installer une méthode Thot (SKILL.md) ou une commande personnalisée (.thot/commands/*.md). À utiliser quand on te demande de créer un skill, de transformer un flux de travail répétitif en méthode réutilisable, ou de savoir où vivent les skills et les commandes.
author: "Prime Agent (skill-creator, MIT) — adapté à Thot"
license: MIT
metadata:
  thot:
    tags: [skills, commands, authoring, extension, workflow]
---

# Écrire une méthode

Une méthode est un dossier contenant un `SKILL.md` : frontmatter YAML puis des
instructions en markdown. Au démarrage, Thot ne lit que le **nom** et la
**description** de chaque méthode ; le corps n'est chargé que lorsque l'outil
`skill` le demande. C'est ce qui permet d'en avoir deux cents sans les payer.

Thot suit la [norme Agent Skills](https://agentskills.io/specification), la
même que Hermes Agent et Prime Agent : un `SKILL.md` écrit pour l'un des trois
se charge tel quel dans les autres.

## Où ça vit

| Emplacement | Portée | Confiance |
|---|---|---|
| `skills/` (livré) | tout le monde | de confiance |
| `~/.thot/skills/<nom>/` | toi, partout | de confiance |
| `<dépôt>/.thot/skills/<nom>/` | ce dépôt, versionné avec lui | **analysé avant chargement** |

La dernière ligne est la seule qui compte pour la sécurité. Un dépôt audité
peut fournir des méthodes, et une méthode est du texte remis au modèle comme
instruction. Thot les passe donc au garde (`thot skills scan`) et refuse ce qui
ressemble à de l'injection, de l'exfiltration ou de la persistance. Écris tes
méthodes de dépôt en conséquence : pas de `curl` vers l'extérieur, pas de
lecture de `~/.thot/`, pas de « ignore les instructions précédentes ».

## Le frontmatter

```yaml
---
name: nom-en-minuscules-avec-tirets
description: Ce que fait la méthode ET quand l'utiliser. C'est la seule chose
  que le modèle voit avant de la charger : sois précis sur le déclencheur.
metadata:
  thot:
    tags: [mots, clés, de, recherche]
---
```

`description` est un argument de vente, pas un titre. « Débogage » ne dit pas
quand s'en servir ; « quand un test échoue de façon intermittente et que la
cause n'est pas évidente » le dit.

Les `tags` sont indexés : `skills("teinte")` retrouve une méthode par ses mots
clés même si son nom ne les contient pas.

## Le corps

Écris pour quelqu'un de compétent qui ne connaît ni ce dépôt ni ce domaine.

- Des étapes numérotées, pas des paragraphes.
- Les commandes exactes, pas leur description.
- Ce qu'il faut faire quand ça rate, pas seulement quand ça marche.
- Un critère d'arrêt : à quoi reconnaît-on que c'est fini.

Cite les outils de Thot par leur nom — `code_map`, `find_symbol`, `callers`,
`audit`, `read_file`, `write_file`, `edit_file`, `run_command`. Une méthode
importée d'un autre agent qui cite `delegate_task` ou `browser_navigate` reste
utile, mais Thot ajoute alors une note disant que ces outils n'existent pas
ici : autant les éviter dès l'écriture.

## Valider

```bash
thot skills scan <dossier-du-skill>   # ce que verrait le garde
thot skills list <mot>                # est-elle trouvable ?
thot skills show <nom>                # que lirait le modèle ?
```

Une méthode que la recherche ne remonte pas est une méthode qui n'existe pas.
Si `thot skills list` sur son sujet ne la retourne pas, corrige les `tags`
avant d'aller plus loin.

## Commande, ou méthode ?

Ce sont deux choses différentes, souvent confondues.

Une **méthode** est de la connaissance : le modèle décide lui-même de la lire
quand la tâche correspond. Une **commande** est un raccourci que *tu* tapes :
un fichier markdown dans `.thot/commands/`, dont le contenu devient le prompt.

```markdown
---
description: Relire un fichier sans rien modifier.
argument-hint: <chemin>
---

Relis $1 et dis-moi ce qui cloche. Ne modifie rien.
```

Enregistré en `.thot/commands/revue.md`, cela crée `/revue src/app.py`.

Substitutions disponibles : `$1`, `$2`… pour les positionnels, `$@` et
`$ARGUMENTS` pour tout, `${@:2}` pour le reste à partir du deuxième, `${@:2:3}`
pour trois arguments à partir du deuxième. Un argument n'est jamais
ré-interprété : s'il contient `$1`, il reste `$1`.

Règle simple : si le modèle doit décider quand s'en servir, c'est une méthode.
Si c'est toi qui décides, c'est une commande.
