#!/usr/bin/env python3
import socket, ssl, json, os, base64
from datetime import datetime
from cryptography.hazmat.primitives import hashes, serialization, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class MiniServer:
    def __init__(self):
        self.host, self.port = 'localhost', 8443
        os.makedirs('received_files', exist_ok=True)
        self.load_certs()
        print(f"🔒 Serveur sur {self.host}:{self.port}")

    def load_certs(self):
        with open('server.crt', 'rb') as f: self.cert = f.read()
        with open('server.key', 'rb') as f: self.key = f.read()
        with open('ca.crt', 'rb') as f: self.ca = f.read()
        self.private_key = serialization.load_pem_private_key(self.key, None)

    def handle_client(self, conn, addr):
        print(f"📞 Client {addr[0]} connecté")
        try:
            cert = conn.getpeercert()
            client = dict(x[0] for x in cert.get_subject().get_components()).get(b'CN', b'Client').decode()
            
            # Métadonnées
            meta = json.loads(conn.recv(4096).decode())
            print(f"📁 Fichier: {meta['filename']} ({meta['file_size']} octets)")
            
            # Déchiffrer clé AES
            aes_key = self.private_key.decrypt(
                base64.b64decode(meta['encrypted_aes_key']),
                padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )
            
            # Recevoir fichier
            data = b''
            while len(data) < meta['file_size']:
                chunk = conn.recv(8192)
                if not chunk: break
                data += chunk
            
            # Déchiffrer avec AES
            iv = base64.b64decode(meta['iv'])
            cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
            decrypted = cipher.decryptor().update(data) + cipher.decryptor().finalize()
            decrypted = decrypted[:-decrypted[-1]]  # Enlever padding
            
            # Sauvegarder
            timestamp = datetime.now().strftime("%H%M%S")
            filename = f"{timestamp}_{client}_{meta['filename']}"
            filepath = os.path.join('received_files', filename)
            
            with open(filepath, 'wb') as f:
                f.write(decrypted)
            
            print(f"✅ Sauvegardé: {filepath}")
            conn.send(json.dumps({'status': 'ok', 'path': filepath}).encode())
            
        except Exception as e:
            print(f"❌ Erreur: {e}")
            conn.send(json.dumps({'status': 'error', 'msg': str(e)}).encode())
        
        finally:
            conn.close()

    def start(self):
        context = ssl.create_ssl_context(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain('server.crt', 'server.key')
        context.load_verify_locations('ca.crt')
        context.verify_mode = ssl.CERT_REQUIRED
        
        with socket.socket() as sock:
            sock.bind((self.host, self.port))
            sock.listen(5)
            print("🚀 En écoute...")
            
            while True:
                try:
                    conn, addr = sock.accept()
                    ssl_conn = context.wrap_socket(conn, server_side=True)
                    self.handle_client(ssl_conn, addr)
                except KeyboardInterrupt:
                    print("\n👋 Arrêt")
                    break
                except Exception as e:
                    print(f"❌ Erreur connexion: {e}")

if __name__ == "__main__":
    print("=" * 40)
    print("🔐 SERVEUR MINI SÉCURISÉ")
    print("=" * 40)
    try:
        MiniServer().start()
    except Exception as e:
        print(f"❌ Erreur: {e}")
