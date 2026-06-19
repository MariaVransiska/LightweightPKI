from __future__ import annotations

import csv
import os
import time
from datetime import timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from .ca import PKIPaths
from .crypto_utils import ensure_dir, utc_now
from .signing import sign_document, verify_document


def _write_synthetic_document(path: Path, size_bytes: int) -> None:
    ensure_dir(path.parent)
    pattern = b"Internal document benchmark payload.\n"
    with path.open("wb") as file:
        remaining = size_bytes
        while remaining > 0:
            chunk = pattern[: min(len(pattern), remaining)]
            file.write(chunk)
            remaining -= len(chunk)


def run_benchmark(workspace: Path, user_id: str, rounds: int = 20) -> Path:
    paths = PKIPaths(workspace)
    ensure_dir(paths.benchmark_dir)
    sizes = [100 * 1024, 1024 * 1024, 10 * 1024 * 1024]
    result_path = paths.benchmark_dir / "performance_results.csv"

    with result_path.open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(
            csv_file,
            fieldnames=[
                "round",
                "document_size_bytes",
                "sign_time_ms",
                "verify_time_ms",
                "verification_status",
            ],
        )
        writer.writeheader()

        for size in sizes:
            document = paths.benchmark_dir / f"synthetic_{size}.bin"
            _write_synthetic_document(document, size)
            for round_index in range(1, rounds + 1):
                start = time.perf_counter()
                signed = sign_document(workspace, user_id, document)
                sign_time_ms = (time.perf_counter() - start) * 1000

                signature = Path(signed["signature"])
                start = time.perf_counter()
                verified = verify_document(workspace, document, signature)
                verify_time_ms = (time.perf_counter() - start) * 1000

                writer.writerow(
                    {
                        "round": round_index,
                        "document_size_bytes": os.path.getsize(document),
                        "sign_time_ms": f"{sign_time_ms:.4f}",
                        "verify_time_ms": f"{verify_time_ms:.4f}",
                        "verification_status": verified["status"],
                    }
                )

    return result_path


def run_tamper_experiment(workspace: Path, user_id: str) -> Path:
    paths = PKIPaths(workspace)
    ensure_dir(paths.benchmark_dir)
    result_path = paths.benchmark_dir / "tamper_results.csv"
    original = paths.benchmark_dir / "tamper_original.txt"
    renamed = paths.benchmark_dir / "tamper_renamed.txt"
    changed = paths.benchmark_dir / "tamper_changed.txt"
    appended = paths.benchmark_dir / "tamper_appended.txt"

    original.write_text("Approved internal document.\nAmount: 1000000\n", encoding="utf-8")
    signed = sign_document(workspace, user_id, original)
    signature = Path(signed["signature"])

    renamed.write_text(original.read_text(encoding="utf-8"), encoding="utf-8")
    changed.write_text("Approved internal document.\nAmount: 9000000\n", encoding="utf-8")
    appended.write_text(original.read_text(encoding="utf-8") + "Additional unauthorized clause.\n", encoding="utf-8")

    cases = [
        ("Asli", original, "Valid"),
        ("Nama file diubah", renamed, "Valid"),
        ("Isi diubah", changed, "Tidak valid"),
        ("Konten ditambah", appended, "Tidak valid"),
    ]

    with result_path.open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=["condition", "expected_result", "actual_result", "detail"])
        writer.writeheader()
        for condition, document, expected in cases:
            try:
                verify_document(workspace, document, signature)
                actual = "Valid"
                detail = "Verification succeeded"
            except Exception as exc:
                actual = "Tidak valid"
                detail = str(exc)
            writer.writerow(
                {
                    "condition": condition,
                    "expected_result": expected,
                    "actual_result": actual,
                    "detail": detail,
                }
            )

    return result_path


def _self_signed_cert_pem(private_key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey, common_name: str) -> bytes:
    now = utc_now()
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Certificate Size Experiment"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(private_key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.PEM)


def run_certificate_size_comparison(workspace: Path) -> Path:
    paths = PKIPaths(workspace)
    ensure_dir(paths.benchmark_dir)
    result_path = paths.benchmark_dir / "certificate_size_comparison.csv"

    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ecdsa_key = ec.generate_private_key(ec.SECP256R1())
    rows = [
        {
            "algorithm": "RSA 2048",
            "certificate_size_bytes": len(_self_signed_cert_pem(rsa_key, "RSA 2048 Test Certificate")),
            "public_key_size_bytes": len(
                rsa_key.public_key().public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            ),
        },
        {
            "algorithm": "ECDSA P-256",
            "certificate_size_bytes": len(_self_signed_cert_pem(ecdsa_key, "ECDSA P-256 Test Certificate")),
            "public_key_size_bytes": len(
                ecdsa_key.public_key().public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            ),
        },
    ]

    with result_path.open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=["algorithm", "certificate_size_bytes", "public_key_size_bytes"])
        writer.writeheader()
        writer.writerows(rows)

    return result_path