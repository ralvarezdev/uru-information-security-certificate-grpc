from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization
from datetime import datetime, timedelta, timezone

from crypto.ed25519 import ISSUER_PRIVATE_KEY

def generate_certificate_from_public_key(
	public_key,
	issuer_subject,
	common_name: str,
	organization: str,
	organizational_unit: str,
	locality: str,
	state: str,
	country: str,
	certificate_validity_days: int,
):
	"""
	Generate a self-signed X.509 certificate from a public key.

	Args:
		public_key: The public key object.
		issuer_subject: Issuer subject.
		common_name (str): Common Name (CN) for the certificate.
		organization (str): Organization (O) for the certificate.
		organizational_unit (str): Organizational Unit (OU) for the certificate.
		locality (str): Locality (L) for the certificate.
		state (str): State or Province (ST) for the certificate.
		country (str): Country (C) for the certificate.
		certificate_validity_days (int): The number of validity days for the certificate.

	Returns:
		bytes: The PEM-encoded certificate.
	"""
	subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
        x509.NameAttribute(NameOID.LOCALITY_NAME, locality),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
		x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, organizational_unit),
		x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
	cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer_subject
    ).public_key(
        public_key
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.now(timezone.utc)
    ).not_valid_after(
        datetime.now(timezone.utc) + timedelta(days=certificate_validity_days)
    ).sign(
		private_key=ISSUER_PRIVATE_KEY,
		algorithm=None
	)
	return cert.public_bytes(serialization.Encoding.PEM)

def validate_certificate_from_pem_data(certificate_pem: bytes, public_key) -> bool:
	"""
	Validate a certificate against a public key.

	Args:
		certificate_pem (bytes): PEM-encoded certificate.
		public_key: The public key object.

	Returns:
		bool: True if the certificate is valid and matches the public key, False otherwise.
	"""
	try:
		cert = x509.load_pem_x509_certificate(certificate_pem)
		return cert.public_key().public_bytes(
			serialization.Encoding.Raw,
			serialization.PublicFormat.Raw
		) == public_key.public_bytes(
			serialization.Encoding.Raw,
			serialization.PublicFormat.Raw
		)
	except Exception as e:
		print(f"Certificate validation error: {e}")
		return False