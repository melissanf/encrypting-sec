#!/usr/bin/env python3
# ============================================================
#  client.py — Membre 3 | Client sécurisé
#  Connexion SSL, échange de certificats, envoi de fichiers
#  chiffrés AES-256-CBC avec clé RSA-wrappée
# ============================================================

import socket, ssl, json, os, base64, sys
from datetime import datetime
from crypto_utils import (
    load_private_key, load_certificate,
    rsa_encrypt, aes_encrypt_file,
    sign_file, hash_to_hex
)

# ─────────────────────────────────────────────
#  Configuration
# ─────────────────────────────────────────────
SERVER_HOST = 'localhost'
SERVER_PORT  = 8443
CERT_DIR     = 'certs'
KEY_DIR      = 'keys'
TMP_DIR      = 'tmp'

os.makedirs(TMP_DIR, exist_ok=True)


class SecureClient:
    def __init__(self, client_name='client-1'):
        self.client_name = client_name
        safe = client_name.replace('-', '_')
        self.cert_path  = os.path.join(CERT_DIR, f'{safe}.pem')
        self.key_path   = os.path.join(KEY_DIR,  f'{safe}_key.pem')
        self.ca_path    = os.path.join(CERT_DIR, 'ca.pem')

        # Validate files exist
        for p in [self.cert_path, self.key_path, self.ca_path]:
            if not os.path.exists(p):
                raise FileNotFoundError(f'[ERR] Fichier manquant: {p}')

        self.private_key = load_private_key(self.key_path)
        self.cert        = load_certificate(self.cert_path)
        print(f'[OK] Client {client_name} initialisé')

    def _build_ssl_context(self):
        """Créer le contexte SSL avec certificats mutuels."""
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_cert_chain(self.cert_path, self.key_path)
        ctx.load_verify_locations(self.ca_path)
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.check_hostname = False   # hostname = 'localhost' en dev
        return ctx

    def send_file(self, filepath, server_cert_path=None, log_callback=None):
        """
        Envoie un fichier chiffré au serveur.
        Étapes : SSL handshake → chiffrement AES → wrap RSA → envoi → vérification signature
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError(f'Fichier introuvable: {filepath}')

        def log(msg, level='info'):
            ts = datetime.now().strftime('%H:%M:%S')
            print(f'[{ts}] {msg}')
            if log_callback:
                log_callback({'time': ts, 'msg': msg, 'level': level})

        filename = os.path.basename(filepath)
        log(f'Préparation envoi: {filename}')

        # ── 1. Chiffrer le fichier avec AES-256-CBC ──
        enc_path = os.path.join(TMP_DIR, f'enc_{filename}')
        aes_key, iv = aes_encrypt_file(filepath, enc_path)
        log('Fichier chiffré AES-256-CBC')

        # ── 2. Signer le fichier ORIGINAL ──
        signature = sign_file(self.private_key, filepath)
        file_hash = hash_to_hex(filepath)
        log(f'Signature SHA-256: {file_hash[:16]}...')

        # ── 3. Charger le certificat serveur pour obtenir la clé publique RSA ──
        if server_cert_path is None:
            server_cert_path = os.path.join(CERT_DIR, 'server.pem')
        server_cert    = load_certificate(server_cert_path)
        server_pub_key = server_cert.public_key()

        # ── 4. Chiffrer la clé AES avec la clé publique RSA du serveur ──
        encrypted_aes_key = rsa_encrypt(server_pub_key, aes_key)
        log('Clé AES wrappée avec RSA-OAEP du serveur')

        # ── 5. Lire le fichier chiffré ──
        with open(enc_path, 'rb') as f:
            encrypted_data = f.read()

        # ── 6. Construire les métadonnées ──
        meta = {
            'filename':          filename,
            'file_size':         len(encrypted_data),
            'original_size':     os.path.getsize(filepath),
            'encrypted_aes_key': base64.b64encode(encrypted_aes_key).decode(),
            'iv':                base64.b64encode(iv).decode(),
            'signature':         base64.b64encode(signature).decode(),
            'sha256_hash':       file_hash,
            'sender':            self.client_name,
            'timestamp':         datetime.now().isoformat(),
        }

        # ── 7. Connexion SSL et envoi ──
        ctx  = self._build_ssl_context()
        log(f'Connexion SSL vers {SERVER_HOST}:{SERVER_PORT}...')

        with socket.create_connection((SERVER_HOST, SERVER_PORT), timeout=30) as raw:
            with ctx.wrap_socket(raw, server_hostname=SERVER_HOST) as ssl_conn:
                log('Handshake SSL OK — certificats vérifiés mutuellement', 'ok')

                # Envoyer métadonnées
                ssl_conn.sendall(json.dumps(meta).encode() + b'\n')

                # Envoyer données chiffrées
                ssl_conn.sendall(encrypted_data)
                log(f'Fichier envoyé: {len(encrypted_data)} octets chiffrés')

                # Recevoir réponse
                resp_raw = b''
                while True:
                    chunk = ssl_conn.recv(4096)
                    if not chunk:
                        break
                    resp_raw += chunk
                    if b'\n' in resp_raw:
                        break

                resp = json.loads(resp_raw.strip())
                if resp.get('status') == 'ok':
                    log(f'Serveur confirme: {resp.get("message", "OK")}', 'ok')
                else:
                    log(f'Erreur serveur: {resp.get("message")}', 'err')

        # Nettoyage fichier temporaire
        os.remove(enc_path)
        return resp


# ─────────────────────────────────────────────
#  TEST CMD
#  python client.py [client_name] [filepath]
# ─────────────────────────────────────────────
if __name__ == '__main__':
    print('=' * 45)
    print('  CLIENT SECURESHARE — Test CMD')
    print('=' * 45)

    client_name = sys.argv[1] if len(sys.argv) > 1 else 'client-1'
    filepath    = sys.argv[2] if len(sys.argv) > 2 else None

    # Créer un fichier test si aucun fourni
    if filepath is None:
        filepath = 'test_send.txt'
        with open(filepath, 'w') as f:
            f.write(f'Fichier test SecureShare\nEnvoyé par: {client_name}\nDate: {datetime.now()}\n')
        print(f'[INFO] Fichier test créé: {filepath}')

    try:
        client = SecureClient(client_name)
        result = client.send_file(filepath)
        print('\n[RÉSULTAT]', json.dumps(result, indent=2))
        print('\n[OK] Transfert terminé avec succès!')
    except FileNotFoundError as e:
        print(f'\n[ERR] {e}')
        print('      Vérifiez que ca.py a été exécuté et que les certs existent.')
    except ConnectionRefusedError:
        print(f'\n[ERR] Impossible de joindre {SERVER_HOST}:{SERVER_PORT}')
        print('      Assurez-vous que server.py tourne.')
    except Exception as e:
        print(f'\n[ERR] {e}')