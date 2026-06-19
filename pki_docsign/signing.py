from __future__ import annotations

from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from .ca import PKIPaths, is_revoked
from .crypto_utils import (
    b64decode,
    b64encode,
    canonical_json,
    certificate_fingerprint,
    certificate_from_pem,
    certificate_to_pem,
    load_certificate,
    load_private_key,
    sha256_file,
    utc_now,
    write_json,
)

def _subject_value(certificate: x509.Certificate, oid: x509.ObjectIdentifier) -> str:
    values = certificate.subject.get_attributes_for_oid(oid)
    return values[0].value if values else ""

def _signature_payload(document_hash: str, signer_cert_fingerprint: str, timestamp_utc: str) -> dict[str, str]:
    return {
        "algorithm": "ECDSA-P256-SHA256",
        "document_hash_sha256": document_hash,
        "signer_certificate_fingerprint_sha256": signer_cert_fingerprint,
        "timestamp_utc": timestamp_utc,
    }

def sign_document(workspace: Path, user_id: str, document: Path) -> dict[str, str]:
    paths = PKIPaths(workspace)
    private_key = load_private_key(paths.user_key(user_id))
    certificate = load_certificate(paths.user_cert(user_id))
    document_hash = sha256_file(document)
    cert_fingerprint = certificate_fingerprint(certificate)
    timestamp = utc_now().isoformat()
    payload = _signature_payload(document_hash, cert_fingerprint, timestamp)
    signature = private_key.sign(canonical_json(payload), ec.ECDSA(hashes.SHA256()))

    package = {
        "type": "internal-document-signature",
        "version": 1,
        "payload": payload,
        "signature_base64": b64encode(signature),
        "signer": {
            "user_id": _subject_value(certificate, NameOID.USER_ID),
            "common_name": _subject_value(certificate, NameOID.COMMON_NAME),
            "department": _subject_value(certificate, NameOID.ORGANIZATIONAL_UNIT_NAME),
            "certificate_pem": certificate_to_pem(certificate),
        },
    }

    signature_path = paths.signatures_dir / f"{document.name}.{user_id}.sig.json"
    write_json(signature_path, package)
    return {
        "document": str(document),
        "signature": str(signature_path),
        "document_hash_sha256": document_hash,
        "signer_certificate_fingerprint_sha256": cert_fingerprint,
    }

def _verify_certificate_chain(signer_cert: x509.Certificate, ca_cert: x509.Certificate) -> None:
    if signer_cert.issuer != ca_cert.subject:
        raise ValueError("Signer certificate issuer does not match internal CA")
    ca_public_key = ca_cert.public_key()
    if not isinstance(ca_public_key, ec.EllipticCurvePublicKey):
        raise TypeError("CA certificate does not contain an EC public key")
    ca_public_key.verify(
        signer_cert.signature,
        signer_cert.tbs_certificate_bytes,
        ec.ECDSA(signer_cert.signature_hash_algorithm),
    )

def _verify_validity_period(certificate: x509.Certificate) -> None:
    now = utc_now()
    if now < certificate.not_valid_before_utc:
        raise ValueError("Signer certificate is not valid yet")
    if now > certificate.not_valid_after_utc:
        raise ValueError("Signer certificate has expired")

def verify_document(workspace: Path, document: Path, signature_file: Path) -> dict[str, str | bool]:
    paths = PKIPaths(workspace)
    ca_cert = load_certificate(paths.ca_cert)
    package = __import__("json").loads(signature_file.read_text(encoding="utf-8"))
    payload = package["payload"]
    signer_cert = certificate_from_pem(package["signer"]["certificate_pem"])
    cert_fingerprint = certificate_fingerprint(signer_cert)

    if payload["document_hash_sha256"] != sha256_file(document):
        raise ValueError("Document hash mismatch. The document was changed or the wrong file was selected.")
    if payload["signer_certificate_fingerprint_sha256"] != cert_fingerprint:
        raise ValueError("Signer certificate fingerprint mismatch")
    if is_revoked(workspace, cert_fingerprint):
        raise ValueError("Signer certificate has been revoked")

    _verify_validity_period(signer_cert)
    _verify_certificate_chain(signer_cert, ca_cert)

    public_key = signer_cert.public_key()
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise TypeError("Signer certificate does not contain an EC public key")
    try:
        public_key.verify(b64decode(package["signature_base64"]), canonical_json(payload), ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as exc:
        raise ValueError("Invalid document signature") from exc

    return {
        "valid": True,
        "status": "VALID",
        "document": str(document),
        "signer_user_id": package["signer"]["user_id"],
        "signer_common_name": package["signer"]["common_name"],
        "document_hash_sha256": payload["document_hash_sha256"],
        "signed_at_utc": payload["timestamp_utc"],
    }