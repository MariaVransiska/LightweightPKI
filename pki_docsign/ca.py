from __future__ import annotations

import secrets
from datetime import timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .crypto_utils import (
    certificate_fingerprint,
    ensure_dir,
    generate_ec_private_key,
    load_certificate,
    load_private_key,
    read_json,
    save_certificate,
    save_private_key,
    utc_now,
    write_json,
)


class PKIPaths:
    def __init__(self, workspace: Path) -> None:
        self.workspace = workspace
        self.ca_dir = workspace / "ca"
        self.users_dir = workspace / "users"
        self.signatures_dir = workspace / "signatures"
        self.benchmark_dir = workspace / "benchmark"
        self.ca_key = self.ca_dir / "ca_private_key.pem"
        self.ca_cert = self.ca_dir / "ca_certificate.pem"
        self.revocations = self.ca_dir / "revoked_certificates.json"

    def user_dir(self, user_id: str) -> Path:
        return self.users_dir / user_id

    def user_key(self, user_id: str) -> Path:
        return self.user_dir(user_id) / "private_key.pem"

    def user_cert(self, user_id: str) -> Path:
        return self.user_dir(user_id) / "certificate.pem"


def init_ca(workspace: Path, org: str, validity_days: int = 3650) -> dict[str, str]:
    paths = PKIPaths(workspace)
    ensure_dir(paths.ca_dir)
    if paths.ca_key.exists() or paths.ca_cert.exists():
        raise FileExistsError("CA already exists. Delete workspace/ca only if you intentionally want to reinitialize it.")

    private_key = generate_ec_private_key()
    now = utc_now()
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
            x509.NameAttribute(NameOID.COMMON_NAME, f"{org} Internal Root CA"),
        ]
    )
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=validity_days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()), critical=False)
        .sign(private_key, hashes.SHA256())
    )

    save_private_key(paths.ca_key, private_key)
    save_certificate(paths.ca_cert, certificate)
    write_json(paths.revocations, {"revoked": []})
    return {
        "ca_certificate": str(paths.ca_cert),
        "fingerprint_sha256": certificate_fingerprint(certificate),
    }


def issue_certificate(
    workspace: Path,
    user_id: str,
    name: str,
    department: str,
    validity_days: int = 730,
) -> dict[str, str]:
    paths = PKIPaths(workspace)
    if not paths.ca_key.exists() or not paths.ca_cert.exists():
        raise FileNotFoundError("CA has not been initialized. Run init-ca first.")
    if paths.user_key(user_id).exists() or paths.user_cert(user_id).exists():
        raise FileExistsError(f"User certificate already exists for user_id={user_id}")

    ca_key = load_private_key(paths.ca_key)
    ca_cert = load_certificate(paths.ca_cert)
    user_key = generate_ec_private_key()
    now = utc_now()
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Internal Organization"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, department),
            x509.NameAttribute(NameOID.USER_ID, user_id),
            x509.NameAttribute(NameOID.COMMON_NAME, name),
        ]
    )

    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(user_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=validity_days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=False,
                crl_sign=False,
                key_encipherment=False,
                content_commitment=True,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(user_key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )

    save_private_key(paths.user_key(user_id), user_key)
    save_certificate(paths.user_cert(user_id), certificate)
    return {
        "user_id": user_id,
        "private_key": str(paths.user_key(user_id)),
        "certificate": str(paths.user_cert(user_id)),
        "fingerprint_sha256": certificate_fingerprint(certificate),
    }


def load_revocation_list(workspace: Path) -> dict[str, list[dict[str, str]]]:
    paths = PKIPaths(workspace)
    if not paths.revocations.exists():
        write_json(paths.revocations, {"revoked": []})
    return read_json(paths.revocations)  # type: ignore[return-value]


def revoke_certificate(workspace: Path, user_id: str, reason: str) -> dict[str, str]:
    paths = PKIPaths(workspace)
    certificate = load_certificate(paths.user_cert(user_id))
    fingerprint = certificate_fingerprint(certificate)
    revocations = load_revocation_list(workspace)
    existing = {item["fingerprint_sha256"] for item in revocations["revoked"]}
    if fingerprint not in existing:
        revocations["revoked"].append(
            {
                "user_id": user_id,
                "serial_number": str(certificate.serial_number),
                "fingerprint_sha256": fingerprint,
                "reason": reason,
                "revocation_id": secrets.token_hex(8),
                "revoked_at_utc": utc_now().isoformat(),
            }
        )
        write_json(paths.revocations, revocations)
    return {"user_id": user_id, "fingerprint_sha256": fingerprint, "status": "revoked"}


def is_revoked(workspace: Path, fingerprint: str) -> bool:
    revocations = load_revocation_list(workspace)
    return any(item["fingerprint_sha256"] == fingerprint for item in revocations["revoked"])