# pwnagent \[WIP\]

Projet perso de programmation d'un agent IA pour le tri et l'analyse
préliminaire de challenges CTF pwn (exploitation binaire).

L'agent automatise les étapes répétitives de l'analyse statique (checksec,
strings, décompilation) et utilise un LLM pour raisonner sur les résultats et
identifier le type de vulnérabilité.

## Objectif

L'agent ne résoud pas les challenges tout seul. Il fait le tri initial en
identifiant les protections, en décompilant les fonctions clés, en faisant
le diagnostique des vulnérabilités probables. Il permettra de générer un
squelette d'exploit pwntools comme point de départ.

## Architecture

### Pattern : ReAct (Reasoning + Acting)

L'agent fonctionne en boucle itérative. À chaque étape, le LLM raisonne sur ce
qu'il sait, choisit une outil à appeler et décide de la prochaine action en
fonction du résultat obtenu.

L'agent utilisera `checksec` (PIE, canary), `file/readelf` (métadonnées ELF),
`strings` (chaînes, chemins, flags), `Ghidra headless` (décompilation),
`objdump` (sections, GOT/PLT).

### Choix techniques

| Composant | Choix | Justification |
| ------------- | -------------- | -------------- |
| Langage | Python | pwntools |
| Patter | ReAct | Analyse itérative |
| LLM (dev) | Ollama (local) | coût zéro |
| LLM (prod) | Surement Claude | Meilleur raisonnement |

## Feuille de route

### Phase 1 - Fondations

[] Structure du projet et CLI de base
[] Ollama en local
[] Outils simples : checksec, file, readelf, strings
[] Boucle ReAct minimale
[] Test sur un ret2win

### Phase 2 - Décompilation

[] Intégration Ghidra headless
[] Parsing et filtrage de la sortie Ghidra
[] Raisonnement sur le code décompilé
[] Test sur buffer overflow (avec canary et PIE)

### Phase 3 - Génération d'exploit

[] Templates pwntools
[] Génération de squelettes d'exploit contextuels
[] Intǵration d'un API cloud

### Phase 4 - Finalisation

[] Toujours plus de tests
[] Documentation des résultats
