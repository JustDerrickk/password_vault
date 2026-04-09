# Password Vault

Un gestionnaire de mots de passe simple en Python.

## Fonctionnalités

- Authentification par mot de passe maître (hashé avec bcrypt)
- Stockage local sécurisé des mots de passe (base SQLite)
- Interface en ligne de commande (CLI) :
  - Ajouter un mot de passe
  - Voir les mots de passe
  - Supprimer un mot de passe

## Installation

1. Clone le dépôt :
   ```
   git clone https://github.com/JustDerrickk/password_vault
   cd password_vault
   ```
2. Installe les dépendances :
   ```
   pip install -r requirements.txt
   ```

## Utilisation

1. Lance le programme :
   ```
   python app/main.py
   ```
2. Suis les instructions pour créer ton mot de passe maître et gérer tes mots de passe.

## Sécurité

- Le mot de passe maître n'est jamais stocké en clair.
- Les mots de passe enregistrés sont chiffrés en base de données.

## Avertissement

Ce projet est à but uniquement éducatif.

---

**Auteur :** Justderrickk
