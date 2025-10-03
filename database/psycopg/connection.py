from datetime import datetime

import psycopg
from cryptography.hazmat.primitives import serialization

from database.psycopg import (
	POSTGRES_DB,
	POSTGRES_USER,
	POSTGRES_PASSWORD,
	POSTGRES_HOST,
	POSTGRES_PORT,
	logger,
)


def create_connection():
	"""Create a connection to the PostgreSQL database."""
	try:
		conn = psycopg.connect(
			dbname=POSTGRES_DB,
			user=POSTGRES_USER,
			password=POSTGRES_PASSWORD,
			host=POSTGRES_HOST,
			port=POSTGRES_PORT
		)
		logger.info("Connection to the database was successful.")
		return conn
	except Exception as e:
		logger.error(f"An error occurred while connecting to the database: {e}")
		return None

def upsert_organization_key(common_name: str, key_value: bytes) -> bool:
	"""Call the upsert_organization_key function in PostgreSQL.

	Args:
		common_name (str): The common name associated with the organization key.
		key_value (bytes): The organization key value.

	Returns:
		bool: True if the operation was successful, False otherwise.
	"""
	with create_connection() as conn:
		with conn.cursor() as cur:
			try:
				cur.execute(
					"CALL upsert_organization_key(%s, %s);",
					(common_name, key_value)
				)
				conn.commit()
				logger.info(f"Upserted organization key for common name: {common_name}")
				return True
			except Exception as e:
				conn.rollback()
				logger.error(f"An error occurred while upserting the organization key: {e}")
				return False

def revoke_certificate(serial_number: str) -> bool:
	"""Call the revoke_certificate procedure in PostgreSQL.

	Args:
		serial_number (str): The serial number of the certificate to be revoked.

	Returns:
		bool: True if the operation was successful, False otherwise.
	"""
	with create_connection() as conn:
		with conn.cursor() as cur:
			try:
				cur.execute(
					"CALL revoke_certificate(%s);",
					(serial_number,)
				)
				conn.commit()
				logger.info(f"Revoked certificate with serial number: {serial_number}")
				return True
			except Exception as e:
				conn.rollback()
				logger.error(f"An error occurred while revoking the certificate: {e}")
				return False

def check_certificate_validity(serial_number: int) -> bool:
	"""Call the check_certificate_validity procedure in PostgreSQL.

	Args:
		serial_number (int): The serial number of the certificate to check.

	Returns:
		bool: True if the certificate is valid, False otherwise.
	"""
	with create_connection() as conn:
		with conn.cursor() as cur:
			try:
				cur.execute(
					"SELECT check_certificate_validity(%s);",
					(serial_number,)
				)
				result = cur.fetchone()
				if result is not None:
					is_valid = result[0]
					logger.info(f"Certificate with serial number {serial_number} validity: {is_valid}")
					return is_valid
				else:
					logger.warning(f"No certificate found with serial number: {serial_number}")
					return False
			except Exception as e:
				logger.error(f"An error occurred while checking certificate validity: {e}")
				return False

def issue_certificate(serial_number: int, common_name: str, expires_at: datetime) -> bool:
	"""Call the issue_certificate procedure in PostgreSQL.

	Args:
		serial_number (int): The serial number of the issued certificate.
		common_name (str): The common name associated with the issued certificate.
		expires_at (datetime): The expiration timestamp of the issued certificate.

	Returns:
		bool: True if the operation was successful, False otherwise.
	"""
	with create_connection() as conn:
		with conn.cursor() as cur:
			try:
				cur.execute(
					"CALL issue_certificate(%s, %s, %s);",
					(serial_number, common_name, expires_at)
				)
				conn.commit()
				logger.info(f"Issued certificate with serial number: {serial_number}")
				return True
			except Exception as e:
				conn.rollback()
				logger.error(f"An error occurred while issuing the certificate: {e}")
				return False

def get_active_organization_key(common_name: str):
	"""Call the get_active_organization_key function in PostgreSQL.

	Args:
		common_name (str): The common name associated with the organization key.
		
	Returns:
		bytes: The organization key value, or None if not found.
	"""
	with create_connection() as conn:
		with conn.cursor() as cur:
			try:
				cur.execute(
					"SELECT get_active_organization_key(%s);",
					(common_name,)
				)
				result = cur.fetchone()
				if result is not None:
					key_value = result[0]
					logger.info(f"Retrieved active organization key for common name: {common_name}")
					return key_value
				else:
					logger.warning(f"No active organization key found for common name: {common_name}")
					return None
			except Exception as e:
				logger.error(f"An error occurred while retrieving the organization key: {e}")
				return None