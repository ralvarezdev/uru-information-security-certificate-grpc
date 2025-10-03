import os

from dotenv import load_dotenv

from crypto import (
	load_private_key_from_file,
	load_public_key_from_file,
	BASE_DIR
)

# Load environment variables from a .env file
load_dotenv()

# Load issuer's private key from PEM file
ISSUER_PRIVATE_KEY_FILENAME = "issuer_private_key.pem"
ISSUER_PRIVATE_KEY = load_private_key_from_file(
	os.path.join(BASE_DIR, ISSUER_PRIVATE_KEY_FILENAME),
	)

# Load issuer's public key from PEM file
ISSUER_PUBLIC_KEY_FILENAME = "issuer_public_key.pem"
ISSUER_PUBLIC_KEY = load_public_key_from_file(
	os.path.join(BASE_DIR, ISSUER_PUBLIC_KEY_FILENAME),
	)
