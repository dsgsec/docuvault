# DocuVault

DocuVault est un MVP de gestion documentaire multi-tenant : organisations, rôles, documents privés, invitations, partages et journal d’activité. L’application utilise React, FastAPI, PostgreSQL, Nginx et Docker Compose.

## Démarrage local

Prérequis : Docker Desktop avec Docker Compose.

```powershell
docker compose up --build
```

Ouvrir [http://localhost:8080](http://localhost:8080). Le jeu de démonstration synthétique est activé au premier démarrage :

- E-mail : `demo@docuvault.example.com`
- Mot de passe : `DemoVault2026!`
- Organisation : Atelier Horizon

Pour repartir de zéro, supprimer les volumes Compose avec `docker compose down -v`. Cette commande efface les données locales.

Les nouveaux comptes peuvent créer leur organisation. Les invitations sont générées dans l’application et le lien doit être transmis manuellement (aucun service d’envoi d’e-mail n’est configuré dans ce MVP). La personne invitée crée un compte avec l’adresse invitée, puis accepte le code depuis la page Membres.

## Fonctionnalités

- Inscription, connexion et déconnexion par cookie de session HTTP-only, profil et changement de mot de passe.
- Création et sélection d’organisations, membres, rôles et invitations à durée limitée.
- Import (PDF, TXT UTF-8, PNG, JPEG, 15 Mo maximum), recherche, téléchargement et gestion des métadonnées.
- Partages documentaires en lecture ou modification.
- Historique consultable par les propriétaires et administrateurs ; événements de sécurité en JSON sur la sortie standard et dans PostgreSQL.
- Stockage de fichiers sur un volume privé, non servi par Nginx. PostgreSQL n’expose aucun port hôte.

## Notes de sécurité et périmètre

Les autorisations sont contrôlées dans l’API ; une ressource absente et une ressource inaccessible sont toutes deux retournées comme introuvables. Les fichiers sont renommés avec des identifiants générés côté serveur. Les identifiants de session et mots de passe ne sont pas inclus dans les événements.

Les valeurs de secret par défaut de Compose et les identifiants de démonstration sont réservés au développement local. Les sessions aléatoires sont stockées côté serveur sous forme hachée et révoquées à la déconnexion. Nginx limite également les requêtes de connexion et d’inscription. Avant tout déploiement, définir des secrets aléatoires via `POSTGRES_PASSWORD`, désactiver les données de démonstration (`SEED_DEMO=false`), activer HTTPS et définir `COOKIE_SECURE=true`, ajouter des migrations versionnées, un service d’envoi d’invitations et une politique de sauvegarde. Le MVP ne remplace pas une revue de sécurité ni un durcissement de production.

## Tests

Les tests API ciblent notamment l’isolation inter-organisations. Depuis `backend` :

```powershell
pip install -r requirements.txt
pip install -r requirements-dev.txt
pytest
```
