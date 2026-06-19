from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Callable

from .benchmark import run_benchmark, run_certificate_size_comparison, run_tamper_experiment
from .ca import init_ca, issue_certificate, revoke_certificate
from .signing import sign_document, verify_document

DEFAULT_WORKSPACE = Path("workspace")

def _print_result(data: dict[str, object]) -> None:
    print(json.dumps(data, indent=2, sort_keys=True))

def _workspace(args: argparse.Namespace) -> Path:
    return Path(args.workspace)

def cmd_init_ca(args: argparse.Namespace) -> None:
    _print_result(init_ca(_workspace(args), args.org, args.validity_days))

def cmd_issue_cert(args: argparse.Namespace) -> None:
    _print_result(
        issue_certificate(
            _workspace(args),
            user_id=args.user_id,
            name=args.name,
            department=args.department,
            validity_days=args.validity_days,
        )
    )

def cmd_sign(args: argparse.Namespace) -> None:
    _print_result(sign_document(_workspace(args), args.user_id, Path(args.document)))

def cmd_verify(args: argparse.Namespace) -> None:
    _print_result(verify_document(_workspace(args), Path(args.document), Path(args.signature)))

def cmd_revoke(args: argparse.Namespace) -> None:
    _print_result(revoke_certificate(_workspace(args), args.user_id, args.reason))

def cmd_benchmark(args: argparse.Namespace) -> None:
    result_path = run_benchmark(_workspace(args), args.user_id, args.rounds)
    _print_result({"benchmark_results": str(result_path)})

def cmd_tamper_experiment(args: argparse.Namespace) -> None:
    result_path = run_tamper_experiment(_workspace(args), args.user_id)
    _print_result({"tamper_experiment_results": str(result_path)})

def cmd_compare_cert_size(args: argparse.Namespace) -> None:
    result_path = run_certificate_size_comparison(_workspace(args))
    _print_result({"certificate_size_comparison": str(result_path)})

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="internal-doc-pki",
        description="Lightweight internal PKI for organizational document signing.",
    )
    parser.add_argument("--workspace", default=str(DEFAULT_WORKSPACE), help="Directory for CA, users, signatures, and logs.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser("init-ca", help="Create the internal root CA.")
    init_parser.add_argument("--org", required=True, help="Organization name for the internal CA.")
    init_parser.add_argument("--validity-days", type=int, default=3650)
    init_parser.set_defaults(func=cmd_init_ca)

    issue_parser = subparsers.add_parser("issue-cert", help="Issue a signer certificate.")
    issue_parser.add_argument("--user-id", required=True)
    issue_parser.add_argument("--name", required=True)
    issue_parser.add_argument("--department", required=True)
    issue_parser.add_argument("--validity-days", type=int, default=730)
    issue_parser.set_defaults(func=cmd_issue_cert)

    sign_parser = subparsers.add_parser("sign", help="Sign a document.")
    sign_parser.add_argument("--user-id", required=True)
    sign_parser.add_argument("--document", required=True)
    sign_parser.set_defaults(func=cmd_sign)

    verify_parser = subparsers.add_parser("verify", help="Verify a document signature.")
    verify_parser.add_argument("--document", required=True)
    verify_parser.add_argument("--signature", required=True)
    verify_parser.set_defaults(func=cmd_verify)

    revoke_parser = subparsers.add_parser("revoke", help="Revoke a signer certificate.")
    revoke_parser.add_argument("--user-id", required=True)
    revoke_parser.add_argument("--reason", default="Unspecified")
    revoke_parser.set_defaults(func=cmd_revoke)

    benchmark_parser = subparsers.add_parser("benchmark", help="Run signing and verification benchmark.")
    benchmark_parser.add_argument("--user-id", required=True)
    benchmark_parser.add_argument("--rounds", type=int, default=20)
    benchmark_parser.set_defaults(func=cmd_benchmark)

    tamper_parser = subparsers.add_parser("tamper-experiment", help="Run document modification detection experiment.")
    tamper_parser.add_argument("--user-id", required=True)
    tamper_parser.set_defaults(func=cmd_tamper_experiment)

    cert_size_parser = subparsers.add_parser("compare-cert-size", help="Compare RSA 2048 and ECDSA P-256 certificate sizes.")
    cert_size_parser.set_defaults(func=cmd_compare_cert_size)

    return parser

def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        command: Callable[[argparse.Namespace], None] = args.func
        command(args)
        return 0
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    raise SystemExit(main())