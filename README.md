# Lightweight Internal PKI for Document Signing
**II4021 Kriptografi - Lightweight Public Key Infrastructure for Internal Organizational Document Signing**

Sistem ini membuat PKI internal ringan untuk organisasi yang ingin menandatangani dan memverifikasi dokumen digital.

## Fitur

- Membuat internal Root Certificate Authority (CA).
- Menerbitkan sertifikat X.509 untuk user internal.
- Menandatangani dokumen menggunakan ECDSA P-256 dan SHA-256.
- Memverifikasi dokumen, signature, certificate chain, validity period, dan revocation status.
- Mendukung banyak user/signers.
- Mendeteksi perubahan isi dokumen.
- Mendukung certificate revocation.
- Menyediakan benchmark signing dan verification.
- Membandingkan ukuran sertifikat RSA 2048 dan ECDSA P-256.

## Struktur Folder

```text
internal_doc_pki/
├── README.md
├── requirements.txt
├── .gitignore
├── pki_docsign/
│   ├── __init__.py
│   ├── ca.py
│   ├── cli.py
│   ├── crypto_utils.py
│   ├── signing.py
│   └── benchmark.py
├── data/
│   └── documents/
|       ├── manual_approval.txt
|       ├── renamed_manual_approval.txt
│       └── sample.txt
├── script/
│   └── testing.py
└── tests/
    └── smoke_test.py
```

Folder `workspace/` akan dibuat otomatis saat program dijalankan. Folder tersebut berisi CA, certificate user, private key, signature, revocation list, dan hasil benchmark.

**`workspace/` tidak di push ke GitHub** karena berisi private key dan file hasil runtime.

## Instalasi

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Jika library `cryptography` sudah tersedia, virtual environment tidak wajib untuk demo.

## Testing Implementasi

### 1. Membuat Internal CA

```bash
python3 -m pki_docsign.cli --workspace workspace/manual_demo init-ca --org "Manual Demo Organization"
```

### 2. Membuat Sertifikat Beberapa User

```bash
python3 -m pki_docsign.cli --workspace workspace/manual_demo issue-cert --user-id finance_admin --name "Finance Admin" --department "Finance"
python3 -m pki_docsign.cli --workspace workspace/manual_demo issue-cert --user-id legal_manager --name "Legal Manager" --department "Legal"
python3 -m pki_docsign.cli --workspace workspace/manual_demo issue-cert --user-id hr_staff --name "HR Staff" --department "Human Resources"
```

### 3. Signing Dokumen

```bash
python3 -m pki_docsign.cli --workspace workspace/manual_demo sign --user-id finance_admin --document data/documents/sample.txt
```

Output akan menghasilkan file signature seperti:

```text
workspace/manual_demo/signatures/sample.txt.finance_admin.sig.json
```

### 4. Verifikasi Dokumen

```bash
python3 -m pki_docsign.cli --workspace workspace/manual_demo verify --document data/documents/sample.txt --signature workspace/manual_demo/signatures/sample.txt.finance_admin.sig.json
```

Jika valid, output berisi:

```json
"status": "VALID"
```

## Pengujian Modifikasi Dokumen

Jika isi dokumen diubah setelah signing, verifikasi akan gagal:

```text
ERROR: Document hash mismatch. The document was changed or the wrong file was selected.
```

Jika nama file diubah tetapi isi dokumen sama, hasilnya tetap valid karena sistem menandatangani hash isi dokumen, bukan nama file.

## Revocation Test

Cabut sertifikat user:

```bash
python3 -m pki_docsign.cli --workspace workspace/manual_demo revoke --user-id finance_admin --reason "Manual revocation test"
```

Verifikasi signature lama:

```bash
python3 -m pki_docsign.cli --workspace workspace/manual_demo verify --document data/documents/sample.txt --signature workspace/manual_demo/signatures/sample.txt.finance_admin.sig.json
```

Hasil yang diharapkan:

```text
ERROR: Signer certificate has been revoked
```

## Smoke Test

Smoke test digunakan untuk mengecek fitur utama secara otomatis:

```bash
PYTHONPATH=. python3 tests/smoke_test.py
```

Output yang diharapkan:

```text
smoke test passed
```

Smoke test mencakup:

- pembuatan CA;
- penerbitan sertifikat;
- multi-user signing;
- verifikasi dokumen valid;
- deteksi dokumen yang diubah;
- penolakan sertifikat yang dicabut.

## Script Testing

Agar semua pengujian muncul dalam format tabel terminal:

```bash
PYTHONPATH=. python3 -u scripts/run_all_tests_for_paper.py --rounds 30
```

Pengujian ini mencakup:

- CA initialization dan certificate issuance;
- valid document signing and verification;
- multi-user signing and verification;
- document modification detection;
- certificate revocation;
- performance benchmark;
- certificate size comparison.

## Benchmark Performa

```bash
python3 -m pki_docsign.cli --workspace workspace/manual_demo benchmark --user-id legal_manager --rounds 30
```

Hasil disimpan di:

```text
workspace/manual_demo/benchmark/performance_results.csv
```

Ukuran dokumen default:

- 100 KB
- 1 MB
- 10 MB

Kolom hasil:

- `round`
- `document_size_bytes`
- `sign_time_ms`
- `verify_time_ms`
- `verification_status`

## Perbandingan Ukuran Sertifikat

```bash
python3 -m pki_docsign.cli --workspace workspace/manual_demo compare-cert-size
```

Hasil disimpan di:

```text
workspace/manual_demo/benchmark/certificate_size_comparison.csv
```

Testing ini membandingkan:

- RSA 2048
- ECDSA P-256

## Ringkasan Desain

Sistem menggunakan:

- ECDSA P-256 untuk digital signature;
- SHA-256 untuk hashing dokumen;
- X.509 certificate untuk identitas user;
- JSON signature package untuk menyimpan metadata signature;
- revocation list sederhana berbasis JSON.

Alur utama:

1. CA internal membuat private key dan self-signed certificate.
2. CA menerbitkan sertifikat untuk user internal.
3. User menghitung hash dokumen menggunakan SHA-256.
4. User menandatangani payload menggunakan private key.
5. Signature package disimpan sebagai file `.sig.json`.
6. Verifier mengecek hash dokumen, signature, certificate chain, validity period, dan revocation list.

## Kontribusi Implementasi

Kontribusi utama project:

1. Merancang lightweight internal PKI untuk document signing.
2. Mengimplementasikan certificate issuance, document signing, verification, revocation, dan benchmark.
3. Mengevaluasi sistem melalui pengujian performa, deteksi modifikasi dokumen, multi-user signing, revocation, dan perbandingan ukuran sertifikat.