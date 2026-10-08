# uru-information-security-certificate-grpc

**Note:** This repository is archived and read-only.

gRPC microservice for certificate generation and validation, in Python.

Part of a set of Information Security college course (URU) projects forming a secure tender (bid) file submission system, all under `ralvarezdev`:

- **`uru-information-security-certificate-grpc`** — certificate authority gRPC service (port 50053)
- **`uru-information-security-encrypter-grpc`** — encrypts and signs bidder files, forwards them to the decrypter (50051)
- **`uru-information-security-decrypter-grpc`** — receives, stores and decrypts files for the tender owner (50052)
- **`uru-information-security-certificate-app`**, **`-bidder-app`**, **`-admin-app`** — Streamlit UIs to request certificates, submit files and manage files (8503, 8502, 8501)

## What it does

Acts as the certificate authority for the system. Service `Certificate` in `proto/ralvarezdev/certificate.proto`:

- **`IssueCertificate`** — takes subject fields and a public key; streams back the issued certificate
- **`ValidateCertificate`** — client-streams certificate content; returns `Empty` on success
- **`RevokeCertificate`** — revokes a certificate by serial number
- **`GetPublicKeyByCommonName`** — returns the public key for a common name

Certificates are X.509 (`cryptography`) signed with the issuer's Ed25519 key. State is kept in PostgreSQL through `psycopg` stored procedures (`issue_certificate`, `revoke_certificate`, `upsert_organization_key`); the database schema is not part of this repository.

## Project structure

- **`main.py`** — gRPC server (`--host`, `--port`)
- **`crypto/ed25519`**, **`crypto/x509`** — issuer key loading; certificate generation and validation
- **`database/psycopg/connection.py`** — PostgreSQL access
- **`generate_keys.bat`**, **`compile_proto.bat`** — Windows scripts to create the issuer key pair with OpenSSL and compile the proto
- **`Dockerfile`** — python:3.11-slim, exposes 50053

## Configuration and running

Environment variables (git-ignored `.env`): `POSTGRES_DB`, `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_HOST`, `POSTGRES_PORT`, `ISSUER_COMMON_NAME`, `ISSUER_ORGANIZATION`, `ISSUER_ORGANIZATIONAL_UNIT`, `ISSUER_LOCALITY`, `ISSUER_STATE`, `ISSUER_COUNTRY`, `CERTIFICATE_VALIDITY_DAYS`. The files `issuer_private_key.pem` and `issuer_public_key.pem` must exist (`generate_keys.bat` uses `openssl genpkey -algorithm ed25519`).

```bash
pip install -r requirements.txt    # UTF-16 encoded; convert if pip complains
python main.py --host "[::]" --port 50053
python -m grpc_tools.protoc -I=proto --python_out=. --grpc_python_out=. proto/ralvarezdev/certificate.proto   # regenerate stubs
```

## License

GNU General Public License v3.0 (see `LICENSE`).
