from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory

from pki_docsign.ca import init_ca, issue_certificate, revoke_certificate
from pki_docsign.signing import sign_document, verify_document

def main() -> None:
    with TemporaryDirectory() as temp_dir:
        base = Path(temp_dir)
        workspace = base / "workspace"
        document = base / "document.txt"
        document.write_text("Quarterly internal report\n", encoding="utf-8")

        init_ca(workspace, "Smoke Test Org")

        users = [
            ("finance_admin", "Finance Admin", "Finance"),
            ("legal_manager", "Legal Manager", "Legal"),
            ("hr_staff", "HR Staff", "Human Resources"),
        ]
        for user_id, name, department in users:
            issue_certificate(workspace, user_id, name, department)

        multi_user_signatures = {}
        for user_id, _, _ in users:
            signed_by_user = sign_document(workspace, user_id, document)
            verified_by_user = verify_document(workspace, document, Path(signed_by_user["signature"]))
            assert verified_by_user["status"] == "VALID"
            assert verified_by_user["signer_user_id"] == user_id
            multi_user_signatures[user_id] = signed_by_user["signature"]

        issue_certificate(workspace, "alice", "Alice Admin", "Finance")
        signed = sign_document(workspace, "alice", document)
        verified = verify_document(workspace, document, Path(signed["signature"]))
        assert verified["status"] == "VALID"
        assert verified["signer_user_id"] == "alice"
        assert len(set(multi_user_signatures.values())) == len(users)

        document.write_text("Tampered report\n", encoding="utf-8")
        try:
            verify_document(workspace, document, Path(signed["signature"]))
        except ValueError as exc:
            assert "hash mismatch" in str(exc).lower()
        else:
            raise AssertionError("Tampered document should not verify")

        document.write_text("Quarterly internal report\n", encoding="utf-8")
        revoke_certificate(workspace, "alice", "Smoke test revocation")
        try:
            verify_document(workspace, document, Path(signed["signature"]))
        except ValueError as exc:
            assert "revoked" in str(exc).lower()
        else:
            raise AssertionError("Revoked certificate should not verify")

    print("smoke test passed")

if __name__ == "__main__":
    main()