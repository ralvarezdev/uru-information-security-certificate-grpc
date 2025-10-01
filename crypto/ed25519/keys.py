from cryptography.hazmat.primitives import serialization

def load_public_key_from_file(file_path: str):
	"""
	Load a PEM-formatted public key from a file.

	Args:
		file_path (str): Path to the PEM file.

	Returns:
		public_key: The loaded public key object.
	"""
	with open(file_path, 'rb') as f:
		pem_data = f.read()
	return load_public_key_from_pem_data(pem_data)

def load_public_key_from_pem_data(pem_data: bytes):
	"""
	Load a PEM-formatted public key from bytes.

	Args:
		pem_data (bytes): PEM-formatted public key data.

	Returns:
		public_key: The loaded public key object.
	"""
	return serialization.load_pem_public_key(pem_data)

def load_private_key_from_file(file_path: str, password: bytes = None):
	"""
	Load a PEM-formatted private key from a file.

	Args:
		file_path (str): Path to the PEM file.
		password (bytes, optional): Password for encrypted private key. Defaults to None.

	Returns:
		private_key: The loaded private key object.
	"""
	with open(file_path, 'rb') as f:
		pem_data = f.read()
	return load_private_key_from_pem_data(pem_data, password=password)

def load_private_key_from_pem_data(pem_data: bytes, password: bytes = None):
	"""
	Load a PEM-formatted private key from bytes.

	Args:
		pem_data (bytes): PEM-formatted private key data.
		password (bytes, optional): Password for encrypted private key. Defaults to None.

	Returns:
		private_key: The loaded private key object.
	"""
	return serialization.load_pem_private_key(pem_data, password=password)
