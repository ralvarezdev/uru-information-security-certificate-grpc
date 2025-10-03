import os

from dotenv import load_dotenv

from crypto.ed25519.load import load_private_key_from_file, load_public_key_from_file

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

# Data path
DATA_PATH = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))