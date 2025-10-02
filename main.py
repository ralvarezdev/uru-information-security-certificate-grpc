from argparse import ArgumentParser
from concurrent import futures

import grpc
from cryptography import x509
from cryptography.hazmat.primitives import serialization

import ralvarezdev.certificate_pb2 as certificate_pb2
import ralvarezdev.certificate_pb2_grpc as certificate_pb2_grpc
from crypto.ed25519.keys import load_public_key_from_pem_data
from crypto.ed25519.certificate import (
	generate_certificate_from_public_key,
	validate_certificate_from_pem_data,
)
from crypto.ed25519 import (
	ISSUER_SUBJECT,
	ISSUER_PUBLIC_KEY,
	CERTIFICATE_VALIDITY_DAYS,
)
from database.psycopg.connection import (
	upsert_organization_key,
	get_active_organization_key,
)

class CertificateServicer(certificate_pb2_grpc.CertificateServicer):
	def GenerateCertificate(self, request, context):
		# Get the public key from the request
		public_key_pem = request.public_key
		if not public_key_pem:
			context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
			context.set_details('Public key is required')
			print("Missing public key")
			yield certificate_pb2.GenerateCertificateResponse()
			return

		# Check if the public key is valid
		try:
			public_key = load_public_key_from_pem_data(public_key_pem)
		except Exception as e:
			context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
			context.set_details('Invalid public key format')
			print(f"Invalid public key format: {e}")
			yield certificate_pb2.GenerateCertificateResponse()
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
				yield certificate_pb2.GenerateCertificateResponse()
				return

		# Check if the public key common name is already associated with an existing certificate
		if not upsert_organization_key(common_name, public_key):
			context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
			context.set_details(f"Common name '{common_name}' is already associated with an existing certificate")
			print(f"Common name '{common_name}' is already associated with an existing certificate")
			yield certificate_pb2.GenerateCertificateResponse()
			return

		# Generate the certificate
		cert_content = generate_certificate_from_public_key(
			public_key=public_key,
			issuer_subject=ISSUER_SUBJECT,
			common_name=common_name,
			organization=organization,
			organizational_unit=organizational_unit,
			locality=locality,
			state=state,
			country=country,
			certificate_validity_days=CERTIFICATE_VALIDITY_DAYS,
		)

		print(f"Generated certificate for {common_name}")

		# Return the certificate content
		yield certificate_pb2.GenerateCertificateResponse(content=cert_content)

	def ValidateCertificate(self, request, context):
		# Get the certificate from the request
		cert_pem = b""
		for chunk in request:
			cert_pem += chunk.content
		if not cert_pem:
			context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
			context.set_details('Certificate is required')
			print("Missing certificate")
			return certificate_pb2.ValidateCertificateResponse(is_valid=False, details="Missing certificate")

		# Validate the certificate by checking its signature against the issuer public key
		try:
			is_valid = validate_certificate_from_pem_data(cert_pem, ISSUER_PUBLIC_KEY)
		except Exception as e:
			context.set_code(grpc.StatusCode.INTERNAL)
			context.set_details('Error validating certificate')
			print(f"Error validating certificate: {e}")
			return certificate_pb2.ValidateCertificateResponse(is_valid=False, details="Error validating certificate")
		if not is_valid:
			context.set_code(grpc.StatusCode.UNAUTHENTICATED)
			context.set_details('Invalid certificate')
			print("Invalid certificate")
			return certificate_pb2.ValidateCertificateResponse(is_valid=False, details="Invalid certificate")

		# Check if the public key is associated with an active organization key
		print(f"Certificate validation result: {is_valid}")
		cert = x509.load_pem_x509_certificate(cert_pem)
		common_name = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
		public_key = cert.public_key()
		active_public_key = get_active_organization_key(common_name)
		if not active_public_key:
			context.set_code(grpc.StatusCode.NOT_FOUND)
			context.set_details(f'No active organization key found for common name: {common_name}')
			print(f'No active organization key found for common name: {common_name}')
			return certificate_pb2.ValidateCertificateResponse(is_valid=False, details="No active organization key found")
		if public_key.public_bytes(
			serialization.Encoding.Raw,
			serialization.PublicFormat.Raw
			) != active_public_key:
			context.set_code(grpc.StatusCode.UNAUTHENTICATED)
			context.set_details('Certificate public key does not match active organization key')
			print('Certificate public key does not match active organization key')
			return certificate_pb2.ValidateCertificateResponse(is_valid=False, details="Certificate public key does not match active organization key")

		# Return the validation result
		return certificate_pb2.ValidateCertificateResponse(is_valid=is_valid)

	def GetPublicKey(self, request, context):
		# Get the common name from the request
		common_name = request.common_name
		if not common_name:
			context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
			context.set_details('Common name is required')
			print("Missing common name")
			return certificate_pb2.GetPublicKeyResponse()

		# Get the public key from the database
		public_key = get_active_organization_key(common_name)
		if not public_key:
			context.set_code(grpc.StatusCode.NOT_FOUND)
			context.set_details(f'No public key found for common name: {common_name}')
			print(f'No public key found for common name: {common_name}')
			return certificate_pb2.GetPublicKeyResponse()

		print(f"Retrieved public key for {common_name}")
		return certificate_pb2.GetPublicKeyResponse(public_key=public_key)

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