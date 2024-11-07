
# LocalHost Server

LHServer est une application serveur HTTP simple avec authentification basique, conçue pour partager des fichiers d'un répertoire spécifique sur votre réseau local ou sur internet. Cette application est construite en Python en utilisant `tkinter` pour l'interface graphique et le module `http.server` pour les fonctionnalités du serveur.

## Prérequis

Pour exécuter LHServer, vous aurez besoin de Python 3.6 ou supérieur et la permission administrateur. Vous pouvez vérifier votre version de Python avec la commande suivante :

```python
python --version
```

ou

```python
python3 --version
```

Si Python n'est pas installé, veuillez le télécharger et l'installer depuis [le site officiel de Python](https://www.python.org/downloads/).

## Installation

1. Clonez le dépôt Git ou téléchargez le code source de LHServer.
2. Ouvrez un terminal ou une invite de commande dans le répertoire du code source.
3. Il n'y a pas de dépendances externes requises, donc aucune étape d'installation supplémentaire n'est nécessaire.

```bash
git clone https://github.com/justwinlab/LHServer
cd LHServer
cd src
pip install -r requirements.txt
python LHServer.py
```

## Configuration

Avant de démarrer le serveur, vous pouvez configurer l'application en éditant le fichier `config.json`. Si le fichier n'existe pas, il sera créé au premier lancement avec la configuration par défaut suivante :

```json
{
    "directory": "C:/Example Files",
    "port": 8000,
    "ip": "localhost",
    "auth_required": false,
    "username": "justwinlab",
    "password": "password"
}
```

Vous pouvez modifier ces valeurs selon vos besoins.

## Démarrage du Serveur

Pour démarrer le serveur, exécutez le script Python depuis le terminal ou l'invite de commande :

Sur Windows

```bash
python LHServer.py
```

ou sur mac ou linux

```bash
python3 LHServer.py
```

L'interface graphique de LHServer s'ouvrira, vous permettant de démarrer et d'arrêter le serveur, ainsi que de configurer les paramètres du serveur directement depuis l'interface.

## Utilisation

Une fois le serveur démarré, vous pouvez accéder à vos fichiers partagés depuis un navigateur web en naviguant vers `http://<IP>:<Port>` où `<IP>` est l'adresse IP configurée (par défaut `localhost`) et `<Port>` est le numéro de port configuré (par défaut `8000`).

Si l'authentification est activée, vous serez invité à entrer le nom d'utilisateur et le mot de passe configurés.

## Contribution

Les contributions au projet sont les bienvenues. Veuillez suivre les bonnes pratiques de développement et soumettre vos pull requests pour examen.

---

Version 1.2.4
Created by justwinlab
