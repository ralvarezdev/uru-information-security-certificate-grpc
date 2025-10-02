import os

from dotenv import load_dotenv
from cryptography import x509
from cryptography.x509.oid import NameOID

from crypto.ed25519.keys import load_private_key_from_file, load_public_key_from_file

# Load environment variables from a .env file
load_dotenv()

# Get the base directory of the project
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

# Load issuer's private key from PEM file
ISSUER_PRIVATE_KEY_FILENAME = "issuer_private_key.pem"
ISSUER_PRIVATE_KEY = load_private_key_from_file(os.path.join(BASE_DIR, ISSUER_PRIVATE_KEY_FILENAME))

# Load issuer's public key from PEM file
ISSUER_PUBLIC_KEY_FILENAME = "issuer_public_key.pem"
ISSUER_PUBLIC_KEY = load_public_key_from_file(os.path.join(BASE_DIR, ISSUER_PUBLIC_KEY_FILENAME))

# Load issuer details from environment variables
ISSUER_COMMON_NAME = os.getenv("ISSUER_COMMON_NAME")
ISSUER_ORGANIZATION = os.getenv("ISSUER_ORGANIZATION")
ISSUER_ORGANIZATIONAL_UNIT = os.getenv("ISSUER_ORGANIZATIONAL_UNIT")
ISSUER_LOCALITY = os.getenv("ISSUER_LOCALITY")
ISSUER_STATE = os.getenv("ISSUER_STATE")
ISSUER_COUNTRY = os.getenv("ISSUER_COUNTRY")

ISSUER_SUBJECT = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, ISSUER_COUNTRY),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, ISSUER_STATE),
	x509.NameAttribute(NameOID.LOCALITY_NAME, ISSUER_LOCALITY),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, ISSUER_ORGANIZATION),
	x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ISSUER_ORGANIZATIONAL_UNIT),
	x509.NameAttribute(NameOID.COMMON_NAME, ISSUER_COMMON_NAME),
])

# Load certificate validity period from environment variables
CERTIFICATE_VALIDITY_DAYS = int(os.getenv("CERTIFICATE_VALIDITY_DAYS"))