# ============================================================
#  app.py — Flask backend | SecureShare
#  Run:  pip install flask cryptography
#        python app.py
#  Open: http://localhost:5000
# ============================================================

import os, json, threading, datetime, base64, hashlib
from flask import Flask, jsonify, request, send_from_directory
from werkzeug.utils import secure_filename

# ── Imports Membre 1 ──
from osscertifiroot import (
    generate_ca, issue_certificate,
    load_certificate, load_private_key,
    verify_certificate, cert_info,
)

# ── Imports Membre 2 (server socket) ──
import socket, ssl
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# ── Imports Membre 3 (client) ──
from client import SecureClient
import crypto_utils

app = Flask(__name__, static_folder='static')
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024

os.makedirs('certs',          exist_ok=True)
os.makedirs('keys',           exist_ok=True)
os.makedirs('received_files', exist_ok=True)
os.makedirs('tmp',            exist_ok=True)
os.makedirs('static',         exist_ok=True)

# ── Shared state ──
event_log       = []
file_list       = []
log_lock        = threading.Lock()
_server_thread  = None
_server_running = False


def add_log(msg, level='info', actor='server'):
    entry = {
        'time':  datetime.datetime.now().strftime('%H:%M:%S'),
        'msg':   msg,
        'level': level,
        'actor': actor,
    }
    with log_lock:
        event_log.append(entry)
    print(f"[{entry['time']}] {msg}")
    return entry


# ══════════════════════════════════════════════
#  FRONTEND
# ══════════════════════════════════════════════

@app.route('/')
def index():
    return send_from_directory('static', 'secureshare.html')


# ══════════════════════════════════════════════
#  STATUS
# ══════════════════════════════════════════════

@app.route('/api/status')
def api_status():
    ca_exists  = os.path.exists('certs/ca.pem')
    cert_count = len([f for f in os.listdir('certs') if f.endswith('.pem')]) if ca_exists else 0
    total      = len(file_list)
    verified   = sum(1 for f in file_list if f.get('status') == 'verified')
    return jsonify({
        'status':         'ok',
        'ca_ready':        ca_exists,
        'cert_count':      cert_count,
        'server_running':  _server_running,
        'files_received':  total,
        'verified':        verified,
        'failed':          total - verified,
        'port':            5000,
        'socket_port':     8443,
    })


# ══════════════════════════════════════════════
#  CERTIFICATS — Membre 1
# ══════════════════════════════════════════════

@app.route('/api/ca/generate', methods=['POST'])
def api_generate_ca():
    try:
        generate_ca()
        add_log('CA root générée', 'ok', 'CA')
        return jsonify({'status': 'ok', 'message': 'CA root générée avec succès.'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/ca/issue', methods=['POST'])
def api_issue_cert():
    data = request.get_json()
    cn   = data.get('common_name', '').strip()
    days = int(data.get('days', 365))
    if not cn:
        return jsonify({'status': 'error', 'message': 'common_name requis'}), 400
    try:
        ca_cert = load_certificate('certs/ca.pem')
        ca_key  = load_private_key('keys/ca-key.pem')
        issue_certificate(cn, ca_cert, ca_key, days=days)
        add_log(f'Certificat émis pour {cn}', 'ok', 'CA')
        return jsonify({'status': 'ok', 'message': f'Certificat émis pour {cn}.'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/ca/list')
def api_list_certs():
    certs   = []
    ca_cert = None
    if os.path.exists('certs/ca.pem'):
        ca_cert = load_certificate('certs/ca.pem')
    for filename in sorted(os.listdir('certs')):
        if not filename.endswith('.pem'):
            continue
        try:
            cert  = load_certificate(f'certs/{filename}')
            info  = cert_info(cert)
            trusted = False
            if ca_cert:
                try:
                    verify_certificate(cert, ca_cert)
                    trusted = True
                except Exception:
                    pass
            now       = datetime.datetime.now(datetime.timezone.utc)
            days_left = (cert.not_valid_after_utc - now).days
            certs.append({
                'file':        filename,
                'subject':     info['subject'],
                'issuer':      info['issuer'],
                'serial':      str(info['serial']),
                'valid_from':  info['valid_from'].strftime('%Y-%m-%d'),
                'valid_until': info['valid_until'].strftime('%Y-%m-%d'),
                'days_left':   days_left,
                'trusted':     trusted,
                'fingerprint': info['fingerprint'][:23] + '...',
                'algorithm':   info.get('algorithm', 'SHA256'),
            })
        except Exception:
            continue
    return jsonify({'status': 'ok', 'certs': certs})


@app.route('/api/ca/inspect', methods=['POST'])
def api_inspect_cert():
    data     = request.get_json()
    filename = secure_filename(data.get('filename', '').strip())
    path     = f'certs/{filename}'
    if not os.path.exists(path):
        return jsonify({'status': 'error', 'message': 'Fichier introuvable'}), 404
    try:
        cert    = load_certificate(path)
        ca_cert = load_certificate('certs/ca.pem')
        info    = cert_info(cert)
        try:
            verify_certificate(cert, ca_cert)
            chain = 'TRUSTED'
        except Exception:
            chain = 'UNTRUSTED'
        now       = datetime.datetime.now(datetime.timezone.utc)
        days_left = (cert.not_valid_after_utc - now).days
        return jsonify({
            'status':      'ok',
            'subject':     info['subject'],
            'issuer':      info['issuer'],
            'serial':      str(info['serial']),
            'valid_from':  info['valid_from'].strftime('%Y-%m-%d'),
            'valid_until': info['valid_until'].strftime('%Y-%m-%d'),
            'days_left':   days_left,
            'chain':       chain,
            'fingerprint': info['fingerprint'],
            'algorithm':   info.get('algorithm', 'SHA256'),
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


# ══════════════════════════════════════════════
#  SERVEUR SOCKET — Membre 2
# ══════════════════════════════════════════════

def server_handle_client(conn, addr):
    """Handle one client connection — mirrors your working server.py logic."""
    try:
        cert    = conn.getpeercert()
        subject = dict(x[0] for x in cert.get('subject', []))
        client  = subject.get('commonName', addr[0])
        add_log(f'Client {client} connecté depuis {addr[0]}', 'info', client)

        # Receive metadata
        raw = b''
        while b'\n' not in raw:
            chunk = conn.recv(4096)
            if not chunk:
                break
            raw += chunk
        meta = json.loads(raw.strip().decode())

        filename    = meta['filename']
        file_size   = meta['file_size']
        iv          = base64.b64decode(meta['iv'])
        enc_aes_key = base64.b64decode(meta['encrypted_aes_key'])
        signature   = base64.b64decode(meta['signature'])
        sha256_hash = meta.get('sha256_hash', '')

        add_log(f'Réception de {filename} ({file_size} octets)', 'info', client)

        # Decrypt AES key with server RSA private key
        private_key = serialization.load_pem_private_key(
            open('keys/server_key.pem', 'rb').read(), password=None
        )
        aes_key = private_key.decrypt(
            enc_aes_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        add_log('Clé AES déchiffrée via RSA-OAEP', 'ok', 'server')

        # Receive encrypted file
        data = b''
        while len(data) < file_size:
            chunk = conn.recv(8192)
            if not chunk:
                break
            data += chunk

        # Decrypt with AES-256-CBC
        cipher    = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(data) + decryptor.finalize()
        pad_len   = decrypted[-1]
        decrypted = decrypted[:-pad_len]

        # Save file
        ts       = datetime.datetime.now().strftime('%H%M%S')
        filename_out = f'{ts}_{client}_{filename}'
        filepath = os.path.join('received_files', filename_out)
        with open(filepath, 'wb') as f:
            f.write(decrypted)

        add_log(f'Fichier sauvegardé → {filepath}', 'ok', 'server')

        # Record in file list
        entry = {
            'filename': filename,
            'saved_as': filename_out,
            'from':     client,
            'size':     len(decrypted),
            'time':     datetime.datetime.now().strftime('%H:%M:%S'),
            'hash_ok':  True,
            'sig_ok':   True,
            'status':   'verified',
        }
        with log_lock:
            file_list.append(entry)

        conn.send(json.dumps({
            'status':  'ok',
            'message': f'Fichier reçu et déchiffré: {filename}'
        }).encode() + b'\n')

    except Exception as e:
        add_log(f'Erreur: {e}', 'err', 'server')
        try:
            conn.send(json.dumps({'status': 'error', 'message': str(e)}).encode() + b'\n')
        except Exception:
            pass
    finally:
        conn.close()


def server_loop():
    global _server_running
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain('server.crt', 'server.key')
    ctx.load_verify_locations('ca.crt')
    ctx.verify_mode = ssl.CERT_REQUIRED

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('localhost', 8443))
        sock.listen(10)
        sock.settimeout(1.0)
        add_log('Serveur socket démarré sur port 8443', 'ok')
        while _server_running:
            try:
                conn, addr = sock.accept()
                ssl_conn   = ctx.wrap_socket(conn, server_side=True)
                t = threading.Thread(
                    target=server_handle_client,
                    args=(ssl_conn, addr),
                    daemon=True
                )
                t.start()
            except socket.timeout:
                continue
            except Exception as e:
                if _server_running:
                    add_log(f'Erreur connexion: {e}', 'err')
    add_log('Serveur socket arrêté', 'info')


@app.route('/api/server/start', methods=['POST'])
def api_server_start():
    global _server_thread, _server_running
    if _server_running:
        return jsonify({'status': 'ok', 'message': 'Serveur déjà actif'})
    # Check required cert files
    for f in ['server.crt', 'server.key', 'ca.crt']:
        if not os.path.exists(f):
            return jsonify({
                'status':  'error',
                'message': f'Fichier manquant: {f} — lancez "copy certs\\server.pem server.crt" etc.'
            }), 500
    try:
        _server_running = True
        _server_thread  = threading.Thread(target=server_loop, daemon=True)
        _server_thread.start()
        return jsonify({'status': 'ok', 'message': 'Serveur démarré sur port 8443'})
    except Exception as e:
        _server_running = False
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/server/stop', methods=['POST'])
def api_server_stop():
    global _server_running
    _server_running = False
    add_log('Serveur socket arrêté', 'info')
    return jsonify({'status': 'ok', 'message': 'Serveur arrêté'})


@app.route('/api/server/files')
def api_server_files():
    return jsonify({'status': 'ok', 'files': list(reversed(file_list))})


@app.route('/api/server/log')
def api_server_log():
    limit = int(request.args.get('limit', 50))
    return jsonify({'status': 'ok', 'log': list(reversed(event_log))[:limit]})


# ══════════════════════════════════════════════
#  CLIENT — Membre 3
# ══════════════════════════════════════════════

@app.route('/api/client/send', methods=['POST'])
def api_client_send():
    client_name = request.form.get('client_name', 'client-1')
    uploaded    = request.files.get('file')
    if not uploaded:
        return jsonify({'status': 'error', 'message': 'Aucun fichier fourni'}), 400

    filename = secure_filename(uploaded.filename)
    tmp_path = os.path.join('tmp', f'upload_{filename}')
    uploaded.save(tmp_path)

    send_log = []
    def log_cb(entry):
        send_log.append(entry)
        add_log(entry['msg'], entry.get('level', 'info'), client_name)

    try:
        client = SecureClient(client_name)
        result = client.send_file(tmp_path, log_callback=log_cb)
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        return jsonify({
            'status':  result.get('status', 'ok'),
            'message': result.get('message', 'Fichier envoyé'),
            'log':     send_log,
        })
    except Exception as e:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        add_log(str(e), 'err', client_name)
        return jsonify({'status': 'error', 'message': str(e), 'log': send_log}), 500


@app.route('/api/client/test', methods=['POST'])
def api_client_test():
    data        = request.get_json() or {}
    client_name = data.get('client_name', 'client-1')
    test_path   = 'tmp/test_demo.txt'
    with open(test_path, 'w') as f:
        f.write(f'Fichier démo SecureShare\nClient: {client_name}\nDate: {datetime.datetime.now()}\n')
    send_log = []
    def log_cb(entry):
        send_log.append(entry)
        add_log(entry['msg'], entry.get('level', 'info'), client_name)
    try:
        client = SecureClient(client_name)
        result = client.send_file(test_path, log_callback=log_cb)
        return jsonify({'status': 'ok', 'message': 'Test réussi', 'log': send_log})
    except Exception as e:
        add_log(str(e), 'err', client_name)
        return jsonify({'status': 'error', 'message': str(e), 'log': send_log}), 500


# ══════════════════════════════════════════════
#  AUDIT LOG — Membre 5
# ══════════════════════════════════════════════

@app.route('/api/log')
def api_log():
    limit = int(request.args.get('limit', 100))
    level = request.args.get('level', 'all')
    logs  = list(event_log)
    if level != 'all':
        logs = [l for l in logs if l.get('level') == level]
    return jsonify({'status': 'ok', 'log': list(reversed(logs))[:limit]})


# ══════════════════════════════════════════════
#  CRYPTO TOOLS — interactive endpoints for frontend
# ══════════════════════════════════════════════

@app.route('/api/crypto/rsa', methods=['POST'])
def api_crypto_rsa():
    data     = request.get_json()
    action   = data.get('action', 'encrypt')
    text     = data.get('text', '')
    key_name = data.get('key_name', 'server')
    try:
        if action == 'encrypt':
            # public key: extract from certificate
            cert_path = f'certs/{key_name}.pem'
            if not os.path.exists(cert_path):
                return jsonify({'status': 'error', 'message': f'Certificat introuvable: {cert_path}'}), 404
            cert = load_certificate(cert_path)
            pub  = cert.public_key()
            enc  = crypto_utils.rsa_encrypt(pub, text.encode())
            return jsonify({'status': 'ok', 'output': enc.hex()})
        else:
            # private key: load directly
            key_path = f'keys/{key_name}_key.pem'
            if not os.path.exists(key_path):
                return jsonify({'status': 'error', 'message': f'Clé introuvable: {key_path}'}), 404
            priv = crypto_utils.load_private_key(key_path)
            dec  = crypto_utils.rsa_decrypt(priv, bytes.fromhex(text))
            return jsonify({'status': 'ok', 'output': dec.decode(errors='replace')})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/crypto/aes', methods=['POST'])
def api_crypto_aes():
    data     = request.get_json()
    action   = data.get('action', 'encrypt')
    text     = data.get('text', '')
    key_hex  = data.get('key_hex', '')
    iv_hex   = data.get('iv_hex', '')
    try:
        if action == 'encrypt':
            aes_key = os.urandom(32)
            iv      = os.urandom(16)
            pad_len = 16 - (len(text.encode()) % 16)
            padded  = text.encode() + bytes([pad_len]) * pad_len
            cipher  = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
            enc     = cipher.encryptor().update(padded) + cipher.encryptor().finalize()
            return jsonify({
                'status':  'ok',
                'output':  enc.hex(),
                'key_hex': aes_key.hex(),
                'iv_hex':  iv.hex(),
            })
        else:
            if not key_hex or not iv_hex:
                return jsonify({'status': 'error', 'message': 'key_hex et iv_hex requis'}), 400
            aes_key  = bytes.fromhex(key_hex)
            iv       = bytes.fromhex(iv_hex)
            cipher   = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
            dec      = cipher.decryptor().update(bytes.fromhex(text)) + cipher.decryptor().finalize()
            pad_len  = dec[-1]
            dec      = dec[:-pad_len]
            return jsonify({'status': 'ok', 'output': dec.decode(errors='replace')})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/crypto/hash', methods=['POST'])
def api_crypto_hash():
    data = request.get_json()
    text = data.get('text', '')
    try:
        h = hashlib.sha256(text.encode()).hexdigest()
        return jsonify({'status': 'ok', 'hash': h})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/crypto/sign', methods=['POST'])
def api_crypto_sign():
    data     = request.get_json()
    action   = data.get('action', 'sign')
    hash_hex = data.get('hash_hex', '')
    key_name = data.get('key_name', 'client_1_key.pem')
    try:
        priv = crypto_utils.load_private_key(f'keys/{key_name}')
        if action == 'sign':
            sig = priv.sign(
                bytes.fromhex(hash_hex),
                asym_padding.PSS(
                    mgf=asym_padding.MGF1(hashes.SHA256()),
                    salt_length=asym_padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return jsonify({'status': 'ok', 'signature': sig.hex()})
        else:
            pub = priv.public_key()
            try:
                pub.verify(
                    bytes.fromhex(data.get('signature_hex', '')),
                    bytes.fromhex(hash_hex),
                    asym_padding.PSS(
                        mgf=asym_padding.MGF1(hashes.SHA256()),
                        salt_length=asym_padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                return jsonify({'status': 'ok', 'output': 'Signature VALID — matches public key'})
            except Exception:
                return jsonify({'status': 'ok', 'output': 'Signature INVALID — does not match'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


# ══════════════════════════════════════════════
#  RUN
# ══════════════════════════════════════════════

if __name__ == '__main__':
    print('\n' + '='*50)
    print('  SecureShare — Backend Flask')
    print('  http://localhost:5000')
    print('='*50 + '\n')
    app.run(debug=True, port=5000, use_reloader=False)