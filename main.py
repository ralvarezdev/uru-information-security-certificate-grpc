import os
from argparse import ArgumentParser
from concurrent import futures

import grpc
from cryptography import x509

from ralvarezdev import certificate_pb2
from ralvarezdev import certificate_pb2_grpc
from crypto.ed25519.load import load_public_key_from_pem_data
from crypto.x509 import (
	generate_certificate_from_public_key,
	validate_certificate_from_pem_data,
)
from crypto.ed25519 import (
	ISSUER_SUBJECT,
	ISSUER_PUBLIC_KEY,
	ISSUER_PRIVATE_KEY,
	CERTIFICATE_VALIDITY_DAYS,
	DATA_PATH,
)
from database.psycopg.connection import (
	upsert_organization_key,
	issue_certificate,
	revoke_certificate,
	check_certificate_validity,
)

class CertificateServicer(certificate_pb2_grpc.CertificateServicer):
	def IssueCertificate(self, request, context):
		# Get the public key from the request
		public_key_pem = request.public_key
		if not public_key_pem:
			context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
			context.set_details('Public key is required')
			print("Missing public key")
			yield certificate_pb2.IssueCertificateResponse()
			return

		# Check if the public key is valid
		try:
			public_key = load_public_key_from_pem_data(public_key_pem)
		except Exception as e:
			context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
			context.set_details('Invalid public key format')
			print(f"Invalid public key format: {e}")
			yield certificate_pb2.IssueCertificateResponse()
			return

		# Get the certificate subject from the request
		common_name = request.common_name
		organization = request.organization
		organizational_unit = request.organizational_unit
		locality = request.locality
		state = request.state
		country = request.country

		# Validate required fields
		required_fields = {
			"common_name": common_name,
			"organization": organization,
			"organizational_unit": organizational_unit,
			"locality": locality,
			"state": state,
			"country": country,
			}

		for field, value in required_fields.items():
			if not value:
				context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
				context.set_details(
					f"{field.replace('_', ' ').title()} is required"
					)
				print(f"Missing required field: {field}")
				yield certificate_pb2.IssueCertificateResponse()
				return

		# Check if the public key common name is already associated with an existing certificate
		if not upsert_organization_key(common_name, public_key):
			context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
			context.set_details(f"Common name '{common_name}' is already associated with an existing certificate")
			print(f"Common name '{common_name}' is already associated with an existing certificate")
			yield certificate_pb2.IssueCertificateResponse()
			return

		# Generate the certificate
		cert, cert_content = generate_certificate_from_public_key(
			public_key=public_key,
			issuer_subject=ISSUER_SUBJECT,
			issuer_private_key=ISSUER_PRIVATE_KEY,
			common_name=common_name,
			organization=organization,
			organizational_unit=organizational_unit,
			locality=locality,
			state=state,
			country=country,
			certificate_validity_days=CERTIFICATE_VALIDITY_DAYS,
		)
		print(f"Issued certificate for {common_name}")

		# Get the serial number and expiration date from the certificate
		serial_number = cert.serial_number
		expiration_date = cert.not_valid_after

		# Store the issued certificate in the database
		if not issue_certificate(serial_number, common_name, expiration_date):
			context.set_code(grpc.StatusCode.INTERNAL)
			context.set_details('Error storing issued certificate')
			print("Error storing issued certificate")
			yield certificate_pb2.IssueCertificateResponse()
			return

		# Store the public key in disk
		common_name = common_name.replace(".", "_")
		public_key_filename = f"{common_name}_public_key.pem"
		public_key_path = os.path.join(DATA_PATH, public_key_filename)
		with open(public_key_path, "wb") as f:
			f.write(public_key_pem)
		print(f"Stored public key at {public_key_path}")

		# Return the certificate content
		yield certificate_pb2.IssueCertificateResponse(certificate_content=cert_content)

	def ValidateCertificate(self, request, context):
		# Get the certificate from the request
		cert_bytes = request.certificate_content
		if not cert_bytes:
			context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
			context.set_details('Certificate is required')
			print("Missing certificate")
			return certificate_pb2.Empty()

		# Validate the certificate by checking its signature against the issuer public key
		try:
			is_valid = validate_certificate_from_pem_data(cert_bytes, ISSUER_PUBLIC_KEY)
		except Exception as e:
			context.set_code(grpc.StatusCode.INTERNAL)
			context.set_details('Error validating certificate')
			print(f"Error validating certificate: {e}")
			return certificate_pb2.Empty()
		if not is_valid:
			context.set_code(grpc.StatusCode.UNAUTHENTICATED)
			context.set_details('Invalid certificate')
			print("Invalid certificate")
			return certificate_pb2.Empty()

		# Load the certificate to get its serial number
		print(f"Certificate validation result: {is_valid}")
		cert = x509.load_pem_x509_certificate(cert_bytes)
		serial_number = cert.serial_number

		# Check if the certificate is revoked or expired in the database
		if not check_certificate_validity(serial_number):
			context.set_code(grpc.StatusCode.UNAUTHENTICATED)
			context.set_details('Certificate is revoked or expired')
			print("Certificate is revoked or expired")
			return certificate_pb2.Empty()

		# Return the validation result
		return certificate_pb2.Empty()

	def RevokeCertificate(self, request, context):
		# Get the serial number from the request
		serial_number = request.serial_number
		if not serial_number:
			context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
			context.set_details('Serial number is required')
			print("Missing serial number")
			return certificate_pb2.Empty()

		# Revoke the certificate in the database
		if not revoke_certificate(serial_number):
			context.set_code(grpc.StatusCode.INTERNAL)
			context.set_details('Error revoking certificate or certificate not found')
			print("Error revoking certificate or certificate not found")
			return certificate_pb2.Empty()

		print(f"Revoked certificate with serial number: {serial_number}")
		return certificate_pb2.Empty()

	def GetPublicKeyByCommonName(self, request, context):
		# Get the common name from the request
		common_name = request.common_name
		if not common_name:
			context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
			context.set_details('Common name is required')
			print("Missing common name")
			return certificate_pb2.GetPublicKeyByCommonNameResponse()

		# Load the public key from disk
		common_name = common_name.replace(".", "_")
		public_key_filename = f"{common_name}_public_key.pem"
		public_key_path = os.path.join(DATA_PATH, public_key_filename)
		if not os.path.exists(public_key_path):
			context.set_code(grpc.StatusCode.NOT_FOUND)
			context.set_details('Public key not found')
			print(f"Public key not found for common name: {common_name}")
			return certificate_pb2.GetPublicKeyByCommonNameResponse()

		with open(public_key_path, "rb") as f:
			public_key_pem = f.read()

		print(f"Retrieved public key for common name: {common_name}")
		return certificate_pb2.GetPublicKeyByCommonNameResponse(public_key=public_key_pem)

def serve(host: str, port: int):
	"""
	Start the gRPC server.

	Args:
		host (str): Host to listen on.
		port (int): Port to listen on.
	"""
	# Create gRPC server
	server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))

	# Register the servicer
	certificate_pb2_grpc.add_CertificateServicer_to_server(
		CertificateServicer(),
		server,
		)
	server.add_insecure_port(host + ':' + str(port))
	server.start()
	server.wait_for_termination()


if __name__ == '__main__':
	# Get port from arguments
	parser = ArgumentParser()
	parser.add_argument('--host', type=str, default='localhost', help='Host to listen on')
	parser.add_argument('--port', type=int, help='Port to listen on')
	args = parser.parse_args()
	print(f'Starting server on {args.host}:{args.port}')

	# Start the gRPC server
	serve(args.host, args.port)