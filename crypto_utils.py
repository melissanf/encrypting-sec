# crypto_utils.py — Module cryptographique partagé
# Membre 4 — Crypto Core
# Importé par : client.py (Membre 3) et server.py (Membre 2)
# Dépendance : pip install cryptography

from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_pem_x509_certificate
import os


# ══════════════════════════════════════════════════════════
#  SECTION 1 — CHARGEMENT DES CLÉS RSA (lien avec Membre 1)
#  Membre 1 génère les fichiers .pem via OpenSSL
#  On les charge ici pour les donner au client et serveur
# ══════════════════════════════════════════════════════════

def load_private_key(filepath: str):
    """
    Charge la clé privée RSA depuis un fichier .pem (généré par Membre 1 via OpenSSL).
    Utilisé par : Membre 2 (serveur) pour déchiffrer la clé AES
    """
    with open(filepath, "rb") as f:
        return serialization.load_pem_private_key(
            f.read(), password=None, backend=default_backend()
        )


def load_public_key(filepath: str):
    """
    Charge la clé publique RSA depuis un fichier .pem (généré par Membre 1).
    Utilisé par : Membre 3 (client) pour chiffrer la clé AES avant envoi
    """
    with open(filepath, "rb") as f:
        return serialization.load_pem_public_key(
            f.read(), backend=default_backend()
        )


def load_certificate(filepath: str):
    """
    Charge un certificat X.509 .pem (généré et signé par Membre 1).
    Utilisé par : Membre 2 (vérifier le cert client) et Membre 3 (vérifier le cert serveur)
    """
    with open(filepath, "rb") as f:
        return load_pem_x509_certificate(f.read(), default_backend())


# ══════════════════════════════════════════════════════════
#  SECTION 2 — CHIFFREMENT RSA (lien avec Membre 2 et 3)
#  Membre 3 (client)  → chiffre la clé AES avec la clé publique du serveur
#  Membre 2 (serveur) → déchiffre la clé AES avec sa clé privée
# ══════════════════════════════════════════════════════════

def rsa_encrypt(public_key, data: bytes) -> bytes:
    """
    Chiffre la clé AES avec la clé publique RSA (padding OAEP).
    Appelé par : Membre 3 — client.py
    Retourne   : clé AES chiffrée à envoyer sur le réseau (bytes)
    """
    return public_key.encrypt(
        data,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def rsa_decrypt(private_key, encrypted_data: bytes) -> bytes:
    """
    Déchiffre la clé AES avec la clé privée RSA (padding OAEP).
    Appelé par : Membre 2 — server.py
    Retourne   : clé AES en clair (32 bytes) pour déchiffrer le fichier
    """
    return private_key.decrypt(
        encrypted_data,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


# ══════════════════════════════════════════════════════════
#  SECTION 3 — CHIFFREMENT AES-256-CBC (lien avec Membre 2 et 3)
#  Membre 3 génère la clé AES aléatoire et chiffre le fichier
#  Membre 2 reçoit la clé AES (déchiffrée RSA) et déchiffre le fichier
# ══════════════════════════════════════════════════════════

def aes_encrypt_file(input_path: str, output_path: str) -> tuple:
    """
    Chiffre un fichier avec AES-256-CBC.
    Appelé par : Membre 3 — client.py (avant envoi du fichier)

    Retourne : (aes_key, iv)
        - aes_key : 32 bytes → à chiffrer avec RSA puis envoyer au serveur
        - iv      : 16 bytes → à envoyer en clair avec le fichier chiffré
    """
    aes_key = os.urandom(32)  # clé 256 bits aléatoire (nouvelle à chaque session)
    iv      = os.urandom(16)  # IV 128 bits aléatoire (nouveau à chaque session)

    cipher    = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    with open(input_path, "rb") as f:
        data = f.read()

    # Padding PKCS7 : la taille doit être multiple de 16
    pad_len = 16 - (len(data) % 16)
    data += bytes([pad_len]) * pad_len

    encrypted = encryptor.update(data) + encryptor.finalize()

    with open(output_path, "wb") as f:
        f.write(encrypted)

    return aes_key, iv  # à transmettre au serveur via la socket


def aes_decrypt_file(input_path: str, output_path: str, aes_key: bytes, iv: bytes):
    """
    Déchiffre un fichier AES-256-CBC.
    Appelé par : Membre 2 — server.py (après réception et déchiffrement RSA de la clé)

    Paramètres :
        - aes_key : clé AES récupérée après déchiffrement RSA
        - iv      : reçu en clair depuis le client
    """
    cipher    = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    with open(input_path, "rb") as f:
        encrypted = f.read()

    decrypted = decryptor.update(encrypted) + decryptor.finalize()

    # Retirer le padding PKCS7
    pad_len   = decrypted[-1]
    decrypted = decrypted[:-pad_len]

    with open(output_path, "wb") as f:
        f.write(decrypted)


# ══════════════════════════════════════════════════════════
#  SECTION 4 — HASH SHA-256 (lien avec Membre 5)
#  Membre 5 compare le hash avant/après pour vérifier l'intégrité
# ══════════════════════════════════════════════════════════

def hash_file(filepath: str) -> bytes:
    """
    Calcule le hash SHA-256 d'un fichier.
    Appelé par :
        - Membre 3 : signer le fichier avant envoi
        - Membre 2 : vérifier l'intégrité après réception
        - Membre 5 : comparer hash source vs hash reçu dans les tests
    Retourne : hash en bytes (32 bytes)
    """
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            digest.update(chunk)
    return digest.finalize()


def hash_to_hex(filepath: str) -> str:
    """
    Version lisible du hash SHA-256 (pour les logs et le README de Membre 5).
    Retourne : hash en hexadécimal (string)
    """
    return hash_file(filepath).hex()


# ══════════════════════════════════════════════════════════
#  SECTION 5 — SIGNATURE NUMÉRIQUE (lien avec Membre 2, 3, 5)
#  Membre 3 signe le fichier avec sa clé privée avant envoi
#  Membre 2 vérifie la signature avec le certificat/clé publique du client
#  Membre 5 montre la vérification de signature dans la démo
# ══════════════════════════════════════════════════════════

def sign_file(private_key, filepath: str) -> bytes:
    """
    Signe le hash SHA-256 du fichier avec la clé privée RSA.
    Appelé par : Membre 3 — client.py (avant envoi)
    Retourne   : signature (bytes) à envoyer avec le fichier
    """
    file_hash = hash_file(filepath)
    signature = private_key.sign(
        file_hash,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature


def verify_signature(public_key, filepath: str, signature: bytes) -> bool:
    """
    Vérifie la signature numérique d'un fichier.
    Appelé par : Membre 2 — server.py (après réception)
                 Membre 5 — pour la démo de vérification

    Retourne : True si la signature est valide, False sinon
    """
    file_hash = hash_file(filepath)
    try:
        public_key.verify(
            signature,
            file_hash,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True   # ✓ Fichier authentique, non modifié
    except Exception:
        return False  # ✗ Signature invalide ou fichier altéré


# ══════════════════════════════════════════════════════════
#  TEST RAPIDE — pour vérifier que tout fonctionne
#  Membre 5 utilisera son test end-to-end complet dans test_integration.py
# ══════════════════════════════════════════════════════════

if __name__ == "__main__":

    print("=== Test rapide crypto_utils.py ===\n")

    # Générer une paire de clés RSA pour le test (normalement fournies par Membre 1)
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    public_key = private_key.public_key()

    # [1] Test RSA wrap/unwrap de clé AES
    aes_key_original = os.urandom(32)
    encrypted_key    = rsa_encrypt(public_key, aes_key_original)
    decrypted_key    = rsa_decrypt(private_key, encrypted_key)
    assert aes_key_original == decrypted_key
    print("[✓] RSA encrypt / decrypt : OK")

    # [2] Test AES chiffrement/déchiffrement de fichier
    with open("test_input.txt", "w") as f:
        f.write("Fichier test — TP Sécurité")

    key, iv = aes_encrypt_file("test_input.txt", "test_encrypted.bin")
    aes_decrypt_file("test_encrypted.bin", "test_output.txt", key, iv)

    with open("test_output.txt") as f:
        assert f.read() == "Fichier test — TP Sécurité"
    print("[✓] AES-256-CBC encrypt / decrypt : OK")

    # [3] Test hash SHA-256
    h = hash_to_hex("test_input.txt")
    print(f"[✓] SHA-256 hash : {h[:20]}...")

    # [4] Test signature et vérification
    sig = sign_file(private_key, "test_input.txt")
    assert verify_signature(public_key, "test_input.txt", sig)
    print("[✓] Signature numérique : OK")

    print("\n=== Tous les tests passés ✓ ===")