"""
ssl_utils.py — Auto-generate a self-signed TLS certificate for Unbound DNS Web GUI.

Uses the 'cryptography' library (Apache License 2.0).
  https://github.com/pypa/cryptography

Certificates are generated once and stored next to this file.
Re-generated automatically if missing or expired.

This file is part of an open-source project and contains no proprietary code.
"""

import os
import socket
import ipaddress
import datetime

BASE_DIR  = os.path.dirname(os.path.abspath(__file__))
CERT_FILE = os.path.join(BASE_DIR, 'ssl_cert.pem')
KEY_FILE  = os.path.join(BASE_DIR, 'ssl_key.pem')

# Certificate validity period (days)
CERT_VALIDITY_DAYS = 3650   # 10 years


def _get_local_ips():
    """Collect all local IPs to embed in the SAN so the cert is valid for any interface."""
    ips = {'127.0.0.1', '::1'}
    try:
        hostname = socket.gethostname()
        ips.add(socket.gethostbyname(hostname))
    except Exception:
        pass
    try:
        import subprocess
        out = subprocess.check_output(
            ['hostname', '-I'], stderr=subprocess.DEVNULL
        ).decode()
        for part in out.split():
            part = part.strip()
            if part:
                ips.add(part)
    except Exception:
        pass
    return ips


def _cert_needs_regen():
    """Return True if cert/key are missing or the cert expires within 30 days."""
    if not os.path.exists(CERT_FILE) or not os.path.exists(KEY_FILE):
        return True
    try:
        from cryptography import x509
        with open(CERT_FILE, 'rb') as f:
            cert = x509.load_pem_x509_certificate(f.read())
        # Regenerate if expiring within 30 days
        threshold = datetime.datetime.utcnow() + datetime.timedelta(days=30)
        return cert.not_valid_after_utc.replace(tzinfo=None) < threshold
    except Exception:
        return True


def ensure_ssl_cert():
    """
    Generate a self-signed RSA-2048 certificate with proper SANs if one doesn't exist.
    Returns (cert_path, key_path).

    Dependencies:
        pip install cryptography          # Apache 2.0
    """
    if not _cert_needs_regen():
        return CERT_FILE, KEY_FILE

    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
    except ImportError:
        raise RuntimeError(
            "The 'cryptography' package is required for HTTPS.\n"
            "Install it with:  pip install cryptography\n"
            "It is Apache 2.0 licensed and safe for open-source projects."
        )

    print("[ssl] Generating self-signed TLS certificate…")

    # ── Key ──────────────────────────────────────────────────────────────────
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # ── Subject / Issuer ─────────────────────────────────────────────────────
    hostname = socket.gethostname() or 'unbound-dns-gui'
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME,         hostname),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME,   'Unbound DNS Web GUI'),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, 'Self-Signed'),
    ])

    # ── Subject Alternative Names (SANs) ─────────────────────────────────────
    # Include every local IP + hostname so the cert matches any access method.
    san_entries = [x509.DNSName(hostname), x509.DNSName('localhost')]
    for ip_str in _get_local_ips():
        try:
            san_entries.append(x509.IPAddress(ipaddress.ip_address(ip_str)))
        except ValueError:
            pass

    # ── Build certificate ────────────────────────────────────────────────────
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(seconds=60))
        .not_valid_after(now + datetime.timedelta(days=CERT_VALIDITY_DAYS))
        .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, key_encipherment=True,
                content_commitment=False, data_encipherment=False,
                key_agreement=False, crl_sign=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([
                ExtendedKeyUsageOID.SERVER_AUTH,
                ExtendedKeyUsageOID.CLIENT_AUTH,
            ]),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )

    # ── Write files ───────────────────────────────────────────────────────────
    with open(KEY_FILE, 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    os.chmod(KEY_FILE, 0o600)   # owner read-only

    with open(CERT_FILE, 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"[ssl] Certificate written to  {CERT_FILE}")
    print(f"[ssl] Private key written to  {KEY_FILE}  (chmod 600)")
    print(f"[ssl] Valid for {CERT_VALIDITY_DAYS} days — SANs: {[str(s) for s in san_entries]}")
    return CERT_FILE, KEY_FILE


def get_cert_info():
    """Return a dict with human-readable cert details for the Settings page."""
    if not os.path.exists(CERT_FILE):
        return {'exists': False}
    try:
        from cryptography import x509
        with open(CERT_FILE, 'rb') as f:
            cert = x509.load_pem_x509_certificate(f.read())
        sans = []
        try:
            ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            sans = [str(v) for v in ext.value]
        except Exception:
            pass
        return {
            'exists':    True,
            'subject':   cert.subject.rfc4514_string(),
            'not_before': cert.not_valid_before_utc.strftime('%Y-%m-%d %H:%M UTC'),
            'not_after':  cert.not_valid_after_utc.strftime('%Y-%m-%d %H:%M UTC'),
            'serial':     hex(cert.serial_number),
            'sans':       sans,
            'cert_file':  CERT_FILE,
            'key_file':   KEY_FILE,
        }
    except Exception as e:
        return {'exists': True, 'error': str(e)}