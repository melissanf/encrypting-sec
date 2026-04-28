from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime

def generate_ca():
    # 1. Generate RSA-2048 private key for the CA
    ca_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
 # 2. Build the CA certificate (self-signed)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "CA-root"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureShare"),
    ])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) +
                         datetime.timedelta(days=3650))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )
        .sign(ca_key, hashes.SHA256())
    )
    # 3. Save to files
    with open("certs/ca.pem", "wb") as f:
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))

    with open("keys/ca-key.pem", "wb") as f:
        f.write(ca_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()
        ))

    print("[OK] CA certificate saved to certs/ca.pem")
    return ca_cert, ca_key




# issue and assign cer for client and server
def issue_certificate(common_name, ca_cert, ca_key, days=365):
    # 1. Generate a new RSA key for this entity
    entity_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # 2. Build and sign the certificate with the CA
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureShare"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)   # signed by CA
        .public_key(entity_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) +
                         datetime.timedelta(days=days))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
        .sign(ca_key, hashes.SHA256())   # CA signs it
    )
    # 3. Save cert and private key
    safe_name = common_name.replace("-", "_")
    with open(f"certs/{safe_name}.pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(f"keys/{safe_name}_key.pem", "wb") as f:
        f.write(entity_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()
        ))

    print(f"[OK] Issued cert for {common_name}")
    return cert, entity_key


# --- Run this once to generate everything ---
if __name__ == "__main__":
    ca_cert, ca_key = generate_ca()
    issue_certificate("server",   ca_cert, ca_key)
    issue_certificate("client-1", ca_cert, ca_key)
    issue_certificate("client-2", ca_cert, ca_key)
    print("[OK] All certificates ready in certs/ and keys/")
    
def load_certificate(path):
    """Load a .pem certificate from disk."""
    with open(path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())

def load_private_key(path):
    """Load a .pem private key from disk."""
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def verify_certificate(cert, ca_cert):
    """
    Verify that cert was signed by ca_cert.
    Returns True if valid, raises an exception if not.
    """
    try:
        ca_cert.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            # padding and hash must match what was used when signing
            __import__('cryptography').hazmat.primitives.asymmetric.padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )
        return True
    except Exception as e:
        raise ValueError(f"Certificate verification failed: {e}")
    
def cert_info(cert):
    """Return a dict of the most useful cert fields."""
    return {
        "subject":     cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value,
        "issuer":      cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value,
        "serial":      cert.serial_number,
        "valid_from":  cert.not_valid_before_utc,
        "valid_until": cert.not_valid_after_utc,
        "fingerprint": cert.fingerprint(hashes.SHA256()).hex(":"),
    }
