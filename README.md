# Serveur C2 en DNS Tunneling & Reverse Shell (Python)

Ce projet a été développé dans le cadre d'un projet de cybersécurité (B2). Il implémente un système  de Command & Control (C2) utilisant le protocole DNS (`DNS Tunneling`) pour exfiltrer des données et exécuter des commandes à distance sur une machine cible, contournant ainsi les pare-feux stricts.

---

## Architecture du projet

Le projet fonctionne autour de trois composants principaux écrits en Python :

1. **`server.py` (Serveur C2 & Résolveur DNS) :** 
   - Écoute sur le port `53` en UDP.
   - Fait office de serveur DNS autoritaire pour le domaine du C2 tout en redirigeant les requêtes légitimes vers un DNS externe (Google).
   - Lit les commandes à envoyer depuis un fichier `command.txt` et les renvoie via des enregistrements de type `TXT`.
   - Récupère, réassemble, décode (Base32) et décompresse (`zlib`) les morceaux de données reçus via les sous-domaines.

2. **`client.py` (Machine cible) :**
   - S'exécute sur la machine cible via une boucle de *polling* toutes les 10 secondes.
   - Interroge le serveur pour récupérer sa commande, l'exécute localement via `subprocess` (avec une gestion de timeout et d'erreurs).
   - Compresse le résultat (`zlib`), l'encode en Base32, le découpe en morceaux de 63 caractères maximum (labels DNS) et l'exfiltre via des requêtes DNS.

3. **`exploit.py` (Script de pilotage / Attaquant) :**
   - Permet à l'opérateur de saisir facilement des commandes à distance.
   - Synchronise l'envoi et l'attente des résultats grâce à un marqueur de fin (`$end$`) et un suivi des timestamps.

---

## Fonctionnement technique

* **Le Polling :** Le client envoie régulièrement des requêtes DNS pour vérifier si une instruction est en attente.
* **Le contournement des limites DNS :** Un label de sous-domaine étant limité à 63 caractères, les données de sortie sont compressées (`zlib`) puis encodées (`Base32`) avant d'être fragmentées au format : 
  `[morceau1].[morceau2].c2.monsite.fr`

---

## Installation & Utilisation

### Prérequis
* Python 3.x installé sur les machines.
* Droits administrateurs (ou capacité d'écouter sur le port 53 UDP) pour exécuter le serveur DNS.

### 1. Cloner le dépôt
```bash
git clone [https://github.com/MelCanoe/C2DNS.git](https://github.com/MelCanoe/C2DNS.git)
cd C2DNS