# SecureShare

End-to-end encrypted file transfer platform with mutual TLS authentication, AES-256-CBC encryption, RSA-OAEP key wrapping, and SHA-256 digital signatures.

## Architecture

```
┌─────────────┐     TLS (mTLS)     ┌─────────────┐
│   Client    │ ◄───────────────► │   Server    │
│  client.py  │                   │  app.py      │
└─────────────┘                   └─────────────┘
       │                                  │
       ▼                                  ▼
┌─────────────────────────────────────────────────┐
│                crypto_utils.py                  │
│   RSA-OAEP · AES-256-CBC · SHA-256 · PSS      │
└─────────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────────┐
│              osscertifiroot.py                  │
│     CA generation · Certificate issuance       │
└─────────────────────────────────────────────────┘
```

**Flow:** Client encrypts file with AES-256-CBC → wraps AES key with server's RSA public key → sends over mTLS → server unwraps AES key with its private key → decrypts file → verifies SHA-256 hash and digital signature.

## Quick start

```bash
pip install flask cryptography
python osscertifiroot.py   # Generate CA + certificates (one-time)
python app.py              # Start web UI on http://localhost:5000
```

## API endpoints

### Status
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/status` | System status, CA readiness, file counts |

### Certificate Authority
| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/ca/generate` | Generate root CA |
| POST | `/api/ca/issue` | Issue a new certificate `{common_name, days}` |
| GET | `/api/ca/list` | List all issued certificates |
| POST | `/api/ca/inspect` | Inspect a certificate `{filename}` |

### Server (TLS socket on port 8443)
| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/server/start` | Start the mTLS socket server |
| POST | `/api/server/stop` | Stop the socket server |
| GET | `/api/server/files` | List received files |
| GET | `/api/server/log` | Server event log |

### Client
| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/client/send` | Send an encrypted file (multipart form) |
| POST | `/api/client/test` | Run an end-to-end test |

### Crypto tools
| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/crypto/rsa` | RSA encrypt/decrypt `{action, text, key_name}` |
| POST | `/api/crypto/aes` | AES-256-CBC encrypt/decrypt `{action, text, key_hex, iv_hex}` |
| POST | `/api/crypto/hash` | SHA-256 hash `{text}` |
| POST | `/api/crypto/sign` | Sign/verify `{action, hash_hex, key_name}` |

### Audit
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/log` | Full event log with optional `?level=` and `?limit=` |

## Files

| File | Role |
|------|------|
| `app.py` | Flask web backend |
| `client.py` | Secure TLS client |
| `server.py` | Standalone TLS socket server |
| `crypto_utils.py` | Shared crypto primitives |
| `osscertifiroot.py` | Certificate authority and X.509 management |
| `static/secureshare.html` | Web UI |

## Directories

| Directory | Contents |
|-----------|----------|
| `certs/` | CA certificate and issued certificates (.pem) |
| `keys/` | Private keys (.pem) |
| `received_files/` | Decrypted files received by the server |
| `tmp/` | Temporary upload staging |
