from base64 import urlsafe_b64encode
from getpass import getpass
from pathlib import Path
import sqlite3

import os
import bcrypt
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
MASTER_HASH_FILE = DATA_DIR / "master.hash"
DB_FILE = DATA_DIR / "passwords.db"
SALT_FILE = DATA_DIR / "salt.bin"

def setup_master_password():
    print("Premier lancement de Password vault. Veuillez configurer votre mot de passe maître.")
    while True: 
        password=getpass("Entrez votre mot de passe maître : ")
        confirm=getpass("Confirmez votre mot de passe maître : ")
        if not password:
            print("Le mot de passe ne peut pas être vide. Veuillez réessayer.")
            continue
        if password != confirm:
            print("Les mots de passe ne correspondent pas. Veuillez réessayer.")
            continue
        password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        DATA_DIR.mkdir(exist_ok=True)
        MASTER_HASH_FILE.write_bytes(password_hash)
        print("Mot de passe maître configuré avec succès.")
        return password_hash

def load_or_create_master_hash():
    if not MASTER_HASH_FILE.exists() or MASTER_HASH_FILE.stat().st_size == 0:
        return setup_master_password()
    return MASTER_HASH_FILE.read_bytes().strip()

def verify_master_password(stored_hash: bytes):
    password = getpass("Mot de passe maître : ").strip()
    return bcrypt.checkpw(password.encode("utf-8"), stored_hash)

def init_db():
    DATA_DIR.mkdir(exist_ok=True)
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS passwords (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        service TEXT NOT NULL,
        username TEXT NOT NULL,
        password TEXT NOT NULL
    )""")
    conn.commit()
    conn.close()

def load_or_create_salt() -> bytes:
    DATA_DIR.mkdir(exist_ok=True)
    if not SALT_FILE.exists() or SALT_FILE.stat().st_size == 0:
        salt = os.urandom(16)
        SALT_FILE.write_bytes(salt)
        return salt
    return SALT_FILE.read_bytes()

def derive_key(master_password: str, salt: bytes) -> bytes:
    kdf=PBKDF2HMAC(algorithm=hashes.SHA256(),length=32,salt=salt,iterations=390000,)
    return urlsafe_b64encode(kdf.derive(master_password.encode("utf-8")))

def build_fernet(master_password: str) -> Fernet:
    salt = load_or_create_salt()
    key = derive_key(master_password, salt)
    return Fernet(key)

def add_password(service, username, encrypted_password):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO passwords (service, username, password) VALUES (?, ?, ?)", (service, username, encrypted_password))
    conn.commit()
    conn.close()

def get_all_passwords():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT id, service, username, password FROM passwords")
    rows = cursor.fetchall()
    conn.close()
    return rows

def delete_password(entry_id):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM passwords WHERE id = ?", (entry_id,))
    conn.commit()
    conn.close()

def main():
    print("Bienvenue sur Password Vault")
    stored_hash = load_or_create_master_hash()

    if verify_master_password(stored_hash):
        print("Accès autorisé")
        init_db()
    else:
        print("Mot de passe maître incorrect")

if __name__ == "__main__":
    main()