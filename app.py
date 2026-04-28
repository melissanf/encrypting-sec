# ============================================================
#  app.py  —  Flask backend that connects ca.py to the frontend
#  Run:  pip install flask cryptography
#        python app.py
#  Open: http://localhost:5000
# ============================================================

import os
import json
import datetime
from flask import Flask, jsonify, request, send_from_directory

# Import everything from your ca.py
from osscertifiroot import (
    generate_ca,
    issue_certificate,
    load_certificate,
    load_private_key,
    verify_certificate,
    cert_info,
)

app = Flask(__name__, static_folder="static")

os.makedirs("certs", exist_ok=True)
os.makedirs("keys",  exist_ok=True)


# ─────────────────────────────────────────────
#  Serve the frontend
# ─────────────────────────────────────────────

@app.route("/")
def index():
    """Serve the main HTML frontend."""
    return send_from_directory("static", "secureshare.html")


# ─────────────────────────────────────────────
#  CA routes  (used by Certificates page)
# ─────────────────────────────────────────────

@app.route("/api/ca/generate", methods=["POST"])
def api_generate_ca():
    """Generate the CA root certificate."""
    try:
        generate_ca()
        return jsonify({"status": "ok", "message": "CA root certificate generated."})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/ca/issue", methods=["POST"])
def api_issue_cert():
    """
    Issue a signed certificate.
    Body: { "common_name": "client-3", "days": 365 }
    """
    data = request.get_json()
    cn   = data.get("common_name", "").strip()
    days = int(data.get("days", 365))

    if not cn:
        return jsonify({"status": "error", "message": "common_name is required"}), 400

    try:
        ca_cert = load_certificate("certs/ca.pem")
        ca_key  = load_private_key("keys/ca-key.pem")
        issue_certificate(cn, ca_cert, ca_key, days=days)
        return jsonify({"status": "ok", "message": f"Certificate issued for {cn}."})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/ca/list", methods=["GET"])
def api_list_certs():
    """Return a list of all issued certificates with their details."""
    certs = []
    ca_cert = None

    if os.path.exists("certs/ca.pem"):
        ca_cert = load_certificate("certs/ca.pem")

    for filename in os.listdir("certs"):
        if not filename.endswith(".pem"):
            continue
        try:
            cert = load_certificate(f"certs/{filename}")
            info = cert_info(cert)

            # Check chain trust
            trusted = False
            if ca_cert:
                try:
                    verify_certificate(cert, ca_cert)
                    trusted = True
                except Exception:
                    trusted = False

            # Check expiry
            now       = datetime.datetime.now(datetime.timezone.utc)
            days_left = (cert.not_valid_after_utc - now).days

            certs.append({
                "file":       filename,
                "subject":    info["subject"],
                "issuer":     info["issuer"],
                "serial":     str(info["serial"]),
                "valid_from": info["valid_from"].strftime("%Y-%m-%d"),
                "valid_until":info["valid_until"].strftime("%Y-%m-%d"),
                "days_left":  days_left,
                "trusted":    trusted,
                "fingerprint":info["fingerprint"][:23] + "...",
                "algorithm":  info["algorithm"],
            })
        except Exception:
            continue

    return jsonify({"status": "ok", "certs": certs})


@app.route("/api/ca/inspect", methods=["POST"])
def api_inspect_cert():
    """
    Inspect a certificate by filename.
    Body: { "filename": "server.pem" }
    """
    data     = request.get_json()
    filename = data.get("filename", "").strip()
    path     = f"certs/{filename}"

    if not os.path.exists(path):
        return jsonify({"status": "error", "message": "File not found"}), 404

    try:
        cert    = load_certificate(path)
        ca_cert = load_certificate("certs/ca.pem")
        info    = cert_info(cert)

        try:
            verify_certificate(cert, ca_cert)
            chain = "TRUSTED"
        except Exception:
            chain = "UNTRUSTED"

        now       = datetime.datetime.now(datetime.timezone.utc)
        days_left = (cert.not_valid_after_utc - now).days

        return jsonify({
            "status":      "ok",
            "subject":     info["subject"],
            "issuer":      info["issuer"],
            "serial":      str(info["serial"]),
            "valid_from":  info["valid_from"].strftime("%Y-%m-%d"),
            "valid_until": info["valid_until"].strftime("%Y-%m-%d"),
            "days_left":   days_left,
            "chain":       chain,
            "fingerprint": info["fingerprint"],
            "algorithm":   info["algorithm"],
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# ─────────────────────────────────────────────
#  Server status route  (used by Dashboard)
# ─────────────────────────────────────────────

@app.route("/api/status", methods=["GET"])
def api_status():
    ca_exists = os.path.exists("certs/ca.pem")
    cert_count = len([f for f in os.listdir("certs") if f.endswith(".pem")]) if ca_exists else 0
    return jsonify({
        "status":     "ok",
        "ca_ready":   ca_exists,
        "cert_count": cert_count,
        "server":     "online",
        "port":       5000,
    })


# ─────────────────────────────────────────────
#  Run
# ─────────────────────────────────────────────

if __name__ == "__main__":
    print("\n  SecureShare backend running at http://localhost:5000\n")
    app.run(debug=True, port=5000)