import psycopg

from database.psycopg import (
	POSTGRES_DB,
	POSTGRES_USER,
	POSTGRES_PASSWORD,
	POSTGRES_HOST,
	POSTGRES_PORT
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
		print("Connection to the database was successful.")
		return conn
	except Exception as e:
		print(f"An error occurred while connecting to the database: {e}")
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
					"SELECT upsert_organization_key(%s, %s);",
					(common_name, key_value)
				)
				conn.commit()
				print(f"Upserted organization key for common name: {common_name}")
				return True
			except Exception as e:
				conn.rollback()
				print(f"An error occurred while upserting the organization key: {e}")
				return False

def get_active_organization_key(common_name: str) -> bytes | None:
	"""Retrieve the organization key for a given common name from PostgreSQL.

	Args:
		common_name (str): The common name associated with the organization key.

	Returns:
		bytes | None: The organization key value if found, None otherwise.
	"""
	with create_connection() as conn:
		with conn.cursor() as cur:
			try:
				cur.execute(
					"SELECT get_active_organization_key(%s);",
					(common_name,)
				)
				result = cur.fetchone()
				if result and result[0]:
					print(f"Retrieved organization key for common name: {common_name}")
					return result[0]
				else:
					print(f"No active organization key found for common name: {common_name}")
					return None
			except Exception as e:
				print(f"An error occurred while retrieving the organization key: {e}")
				return None