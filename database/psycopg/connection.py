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

def upsert_decrypter_key(common_name: str, key_value: bytes) -> bool:
	"""Call the upsert_decrypter_key function in PostgreSQL.

	Args:
		common_name (str): The common name associated with the decrypter key.
		key_value (bytes): The decrypter key value.

	Returns:
		bool: True if the operation was successful, False otherwise.
	"""
	with create_connection() as conn:
		with conn.cursor() as cur:
			try:
				cur.execute(
					"SELECT upsert_decrypter_key(%s, %s);",
					(common_name, key_value)
				)
				conn.commit()
				print(f"Upserted decrypter key for common name: {common_name}")
				return True
			except Exception as e:
				conn.rollback()
				print(f"An error occurred while upserting the decrypter key: {e}")
				return False

def get_decrypter_key(common_name: str) -> bytes | None:
	"""Retrieve the decrypter key for a given common name from PostgreSQL.

	Args:
		common_name (str): The common name associated with the decrypter key.

	Returns:
		bytes | None: The decrypter key value if found, None otherwise.
	"""
	with create_connection() as conn:
		with conn.cursor() as cur:
			try:
				cur.execute(
					"SELECT key_value FROM decrypter_keys WHERE common_name = %s;",
					(common_name,)
				)
				result = cur.fetchone()
				if result:
					print(f"Retrieved decrypter key for common name: {common_name}")
					return result[0]
				else:
					print(f"No decrypter key found for common name: {common_name}")
					return None
			except Exception as e:
				print(f"An error occurred while retrieving the decrypter key: {e}")
				return None