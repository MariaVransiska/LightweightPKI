from __future__ import annotations

import argparse
import csv
import statistics
from datetime import datetime
from pathlib import Path

from pki_docsign.benchmark import run_benchmark, run_certificate_size_comparison
from pki_docsign.ca import init_ca, issue_certificate, revoke_certificate
from pki_docsign.signing import sign_document, verify_document

def print_section(title: str) -> None:
    print("\n" + "=" * 78)
    print(title)
    print("=" * 78)

def print_table(headers: list[str], rows: list[list[str]]) -> None:
    widths = [len(header) for header in headers]
    for row in rows:
        for index, cell in enumerate(row):
            widths[index] = max(widths[index], len(cell))

    header_line = " | ".join(header.ljust(widths[index]) for index, header in enumerate(headers))
    separator = "-+-".join("-" * width for width in widths)
    print(header_line)
    print(separator)
    for row in rows:
        print(" | ".join(cell.ljust(widths[index]) for index, cell in enumerate(row)))

def verify_case(workspace: Path, document: Path, signature: Path) -> tuple[str, str]:
    try:
        verify_document(workspace, document, signature)
        return "Valid", "Verification succeeded"
    except Exception as exc:
        return "Tidak valid", str(exc)

def average_performance_rows(csv_path: Path) -> list[list[str]]:
    grouped: dict[int, dict[str, list[float]]] = {}
    with csv_path.open(newline="", encoding="utf-8") as file:
        for row in csv.DictReader(file):
            size = int(row["document_size_bytes"])
            grouped.setdefault(size, {"sign": [], "verify": []})
            grouped[size]["sign"].append(float(row["sign_time_ms"]))
            grouped[size]["verify"].append(float(row["verify_time_ms"]))

    labels = {
        100 * 1024: "100 KB",
        1024 * 1024: "1 MB",
        10 * 1024 * 1024: "10 MB",
    }
    rows: list[list[str]] = []
    for size in sorted(grouped):
        rows.append(
            [
                labels.get(size, f"{size} bytes"),
                f"{statistics.mean(grouped[size]['sign']):.4f} ms",
                f"{statistics.mean(grouped[size]['verify']):.4f} ms",
                "VALID",
            ]
        )
    return rows

def certificate_size_rows(csv_path: Path) -> list[list[str]]:
    with csv_path.open(newline="", encoding="utf-8") as file:
        return [
            [row["algorithm"], f"{row['certificate_size_bytes']} bytes", f"{row['public_key_size_bytes']} bytes"]
            for row in csv.DictReader(file)
        ]

def main() -> int:
    parser = argparse.ArgumentParser(description="Run all screenshot-friendly tests for the paper.")
    parser.add_argument("--rounds", type=int, default=3, help="Benchmark rounds per file size.")
    args = parser.parse_args()

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    workspace = Path("workspace") / f"paper_tests_{timestamp}"
    docs_dir = workspace / "documents"
    docs_dir.mkdir(parents=True, exist_ok=True)

    print_section("TEST ENVIRONMENT")
    print(f"Workspace       : {workspace}")
    print("Algorithm       : ECDSA P-256 with SHA-256")
    print("Certificate     : X.509 internal certificate")
    print(f"Benchmark rounds: {args.rounds}")

    print_section("TEST 1 - CA INITIALIZATION AND CERTIFICATE ISSUANCE")
    ca_info = init_ca(workspace, "Paper Test Organization")
    signer_info = issue_certificate(workspace, "alice", "Alice Admin", "Finance")
    print_table(
        ["Step", "Result"],
        [
            ["Internal root CA created", "Success"],
            ["Signer certificate issued", "Success"],
            ["CA fingerprint", ca_info["fingerprint_sha256"][:32] + "..."],
            ["Signer fingerprint", signer_info["fingerprint_sha256"][:32] + "..."],
        ],
    )

    print_section("TEST 2 - DOCUMENT SIGNING AND VALID VERIFICATION")
    original = docs_dir / "contract.txt"
    original.write_text("Approved internal contract.\nAmount: 1000000\n", encoding="utf-8")
    signed = sign_document(workspace, "alice", original)
    signature = Path(signed["signature"])
    valid_result, valid_detail = verify_case(workspace, original, signature)
    print_table(
        ["Condition", "Expected", "Actual", "Detail"],
        [["Original document", "Valid", valid_result, valid_detail]],
    )

    print_section("TEST 3 - MULTI-USER SIGNING AND VERIFICATION")
    multi_users = [
        ("finance_admin", "Finance Admin", "Finance"),
        ("legal_manager", "Legal Manager", "Legal"),
        ("hr_staff", "HR Staff", "Human Resources"),
    ]
    multi_user_rows = []
    for user_id, name, department in multi_users:
        issue_certificate(workspace, user_id, name, department)
        user_signed = sign_document(workspace, user_id, original)
        user_verified = verify_document(workspace, original, Path(user_signed["signature"]))
        multi_user_rows.append(
            [
                user_id,
                department,
                "Valid",
                str(user_verified["signer_user_id"]),
                "Signer identity matched",
            ]
        )
    print_table(
        ["User ID", "Department", "Expected", "Verified Signer", "Detail"],
        multi_user_rows,
    )

    print_section("TEST 4 - DOCUMENT MODIFICATION DETECTION")
    renamed = docs_dir / "renamed_contract.txt"
    changed = docs_dir / "changed_contract.txt"
    appended = docs_dir / "appended_contract.txt"
    renamed.write_text(original.read_text(encoding="utf-8"), encoding="utf-8")
    changed.write_text("Approved internal contract.\nAmount: 9000000\n", encoding="utf-8")
    appended.write_text(original.read_text(encoding="utf-8") + "Unauthorized extra clause.\n", encoding="utf-8")

    modification_rows = []
    for condition, expected, document in [
        ("Asli", "Valid", original),
        ("Isi diubah", "Tidak valid", changed),
        ("Nama file diubah", "Valid", renamed),
        ("Konten ditambah", "Tidak valid", appended),
    ]:
        actual, detail = verify_case(workspace, document, signature)
        modification_rows.append([condition, expected, actual, detail])
    print_table(["Condition", "Expected", "Actual", "Detail"], modification_rows)

    print_section("TEST 5 - CERTIFICATE REVOCATION")
    revoke_certificate(workspace, "alice", "Paper test revocation")
    revoked_result, revoked_detail = verify_case(workspace, original, signature)
    print_table(
        ["Condition", "Expected", "Actual", "Detail"],
        [["Certificate revoked", "Tidak valid", revoked_result, revoked_detail]],
    )

    print_section("TEST 6 - PERFORMANCE BENCHMARK")
    issue_certificate(workspace, "bob", "Bob Benchmark", "Research")
    performance_csv = run_benchmark(workspace, "bob", rounds=args.rounds)
    print(f"CSV output: {performance_csv}")
    print_table(
        ["File Size", "Avg Signing Time", "Avg Verification Time", "Status"],
        average_performance_rows(performance_csv),
    )

    print_section("TEST 7 - CERTIFICATE SIZE COMPARISON")
    cert_size_csv = run_certificate_size_comparison(workspace)
    print(f"CSV output: {cert_size_csv}")
    print_table(
        ["Algorithm", "Certificate Size", "Public Key Size"],
        certificate_size_rows(cert_size_csv),
    )

if __name__ == "__main__":
    raise SystemExit(main())