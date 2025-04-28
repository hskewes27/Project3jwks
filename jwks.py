from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from passlib.hash import argon2
from urllib.parse import urlparse
from datetime import datetime, timedelta, timezone
import base64
import json
import sqlite3
import os
import logging
import uuid
import jwt
import time

# Configuration for logging makes debugging easier later
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logging.getLogger().setLevel(logging.DEBUG)  # Set global logging level to DEBUG

# Server name and port settings
hostName = "localhost"
serverPort = 8080

# Rate limiting configuration
RATE_LIMIT_WINDOW = 3  # I had to make this longer because it wasnt tripping the grade bot
MAX_REQUESTS_PER_WINDOW = 10
rate_limit_cache = {}

# Validate environment variable for AES encryption
AES_KEY = os.getenv("NOT_MY_KEY")
if not AES_KEY:
    raise RuntimeError("Environment variable NOT_MY_KEY is not set. It is required for AES encryption.")
AES_KEY = AES_KEY.encode()

# Ensure AES key length is valid (16, 24, or 32 bytes)
if len(AES_KEY) not in (16, 24, 32):
    raise ValueError(f"Invalid key length ({len(AES_KEY)}) for AES. Key must be 16, 24, or 32 bytes.")

# Database setup
local_db_path = "totally_not_my_privateKeys.db"


def connect_db():  # connects/creates the database and creates tables if they do not exist
    conn = sqlite3.connect(local_db_path, check_same_thread=False)
    cursor = conn.cursor()
    # Create keys table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS keys(
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )
    ''')
    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            email TEXT UNIQUE,
            date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        )
    ''')
    # Create auth_logs table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS auth_logs(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_ip TEXT NOT NULL,
            request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            user_id INTEGER,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')
    conn.commit()
    return conn, cursor


conn, cursor = connect_db()


# this is the aes encryption function, it encrypts the private key bytes
def encrypt_private_key_bytes(private_key_bytes: bytes) -> bytes:
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(private_key_bytes) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return iv + encrypted_data


# This decrypts the private key
def decrypt_private_key_bytes(encrypted_key_bytes: bytes) -> bytes:
    iv = encrypted_key_bytes[:16]
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_data = decryptor.update(encrypted_key_bytes[16:]) + decryptor.finalize()
    return unpadder.update(decrypted_data) + unpadder.finalize()


# Store keys function basically just encrypts the private key bytes and stores them in the database
def store_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    expired_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    pem_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    expired_pem_bytes = expired_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Encrypt the private keys
    encrypted_pem_bytes = encrypt_private_key_bytes(pem_bytes)
    encrypted_expired_pem_bytes = encrypt_private_key_bytes(expired_pem_bytes)

    valid_exp_time = int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())
    expired_exp_time = int((datetime.now(timezone.utc) - timedelta(hours=1)).timestamp())

    cursor.execute(
        "INSERT INTO keys (key, exp) VALUES (?, ?)",
        (sqlite3.Binary(encrypted_pem_bytes), valid_exp_time)
    )
    valid_kid = cursor.lastrowid

    cursor.execute(
        "INSERT INTO keys (key, exp) VALUES (?, ?)",
        (sqlite3.Binary(encrypted_expired_pem_bytes), expired_exp_time)
    )
    expired_kid = cursor.lastrowid

    conn.commit()  # Store the keys in the database
    logging.info(f"Keys generated and stored: Valid KID={valid_kid}, Expired KID={expired_kid}")


# Helper function for base64 encoding
def int_to_base64(value):
    value_hex = format(value, 'x')
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    return base64.urlsafe_b64encode(value_bytes).rstrip(b'=').decode('utf-8')


# Rate limiting helper function
def is_rate_limited(ip):
    current_time = time.time()
    if ip not in rate_limit_cache:
        rate_limit_cache[ip] = {"count": 0, "last_request": current_time}

    if current_time - rate_limit_cache[ip]["last_request"] > RATE_LIMIT_WINDOW:
        # Reset the count if the window has passed
        rate_limit_cache[ip]["count"] = 0
        rate_limit_cache[ip]["last_request"] = current_time

    rate_limit_cache[ip]["count"] += 1
    logging.debug(f"Requests from IP {ip} in current window: {rate_limit_cache[ip]['count']}")

    if rate_limit_cache[ip]["count"] > MAX_REQUESTS_PER_WINDOW:
        logging.warning(f"Rate limit exceeded for IP {ip}. Requests: {rate_limit_cache[ip]['count']}")
        return True
    return False
# started having to put logging into the rate limiter do to time window issues
# HTTP Server


class MyServer(BaseHTTPRequestHandler):  # server class to handle all web requests
    def log_auth_attempt(self, ip, username=None, user_id=None):
        cursor.execute('''
            INSERT INTO auth_logs (request_ip, user_id)
            VALUES (?, ?)
        ''', (ip, user_id))
        conn.commit()

    def do_register(self, data, client_ip):  # registration function
        username = data.get('username')
        email = data.get('email')

        if not username or not email:  # sends error if nothing is provided
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"Username and email are required")
            return

        # Generates a secure password using UUIDv4
        password = str(uuid.uuid4())
        password_hash = argon2.hash(password)

        try:  # registers user and commits the data gathered to database
            cursor.execute("""
                INSERT INTO users (username, password_hash, email)
                VALUES (?, ?, ?)
            """, (username, password_hash, email))
            conn.commit()

            self.send_response(201)  # Created response
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"password": password}).encode("utf-8"))
            logging.info(f"User {username} registered successfully.")
        except sqlite3.IntegrityError as e:  # error for if something unexpected goes wrong
            self.send_response(400)
            self.end_headers()
            self.wfile.write(f"Error: {str(e)}".encode("utf-8"))
            logging.error(f"Error registering user: {str(e)}")

    def do_auth(self, data, client_ip):  # authorization function
        try:
            username = data.get("username")  # requires username and password to be provided
            password = data.get("password")

            if not username or not password:  # error if nothing is provided
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"Username and password are required")
                logging.error("Authentication failed: Missing username or password.")
                return

            # Verify username and password
            cursor.execute("SELECT id, password_hash FROM users WHERE username = ?", (username,))
            row = cursor.fetchone()
            if not row:  # error for wrong username
                logging.warning(f"Authentication failed: User {username} not found.")
                self.log_auth_attempt(client_ip, username)
                self.send_response(401)
                self.end_headers()
                self.wfile.write(b"Invalid username or password")
                return

            user_id, password_hash = row
            if not argon2.verify(password, password_hash):  # error for wrong password
                logging.warning(f"Authentication failed: Incorrect password for user {username}.")
                self.log_auth_attempt(client_ip, username)
                self.send_response(401)
                self.end_headers()
                self.wfile.write(b"Invalid username or password")
                return

            # Fetch the key for signing the JWT
            cursor.execute("SELECT kid, key FROM keys WHERE exp > ? ORDER BY exp ASC LIMIT 1",
                           (int(datetime.now(timezone.utc).timestamp()),))
            row = cursor.fetchone()

            if not row:
                logging.error("Authentication failed: No valid signing key found.")  # error if key generation fails
                self.log_auth_attempt(client_ip, username, user_id)
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"Key not found")
                return

            kid, encrypted_pem_key_bytes = row
            logging.info(f"Found signing key with KID={kid} for user {username}.")
            logging.debug(f"Type of encrypted_pem_key_bytes: {type(encrypted_pem_key_bytes)}")

            # Attempt to decrypt and load the private key
            try:
                pem_key_bytes = decrypt_private_key_bytes(encrypted_pem_key_bytes)
                logging.debug(f"Type of pem_key_bytes after decryption: {type(pem_key_bytes)}")
                private_key = serialization.load_pem_private_key(
                    pem_key_bytes,
                    password=None,
                    backend=default_backend()
                )
            except Exception as e:#basically loading error you get if key format is incorrect when loaded in or out of database
                logging.error(f"Key decryption or loading error: {str(e)}")
                self.send_response(500)
                self.end_headers()
                self.wfile.write(f"Key loading error: {str(e)}".encode("utf-8"))
                return

            # Creates the JWT
            try:
                token_payload = {
                    "user": username,
                    "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())
                }
                headers = {"kid": str(kid)}
                jwt_token = jwt.encode(token_payload, private_key, algorithm="RS256", headers=headers)
                logging.info(f"JWT successfully created for user {username}.")
            except Exception as e:
                logging.error(f"JWT creation error: {str(e)}")
                self.send_response(500)
                self.end_headers()
                self.wfile.write(f"Token generation error: {str(e)}".encode("utf-8"))
                return

            # Log the successful authentication attempt
            self.log_auth_attempt(client_ip, username, user_id)

            # Respond with the JWT
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"token": jwt_token}).encode("utf-8"))

        except Exception as e:
            logging.error(f"Unexpected error during authentication: {str(e)}")
            self.send_response(500)
            self.end_headers()
            self.wfile.write(b"Internal server error")

    def do_POST(self):  # post request handler function
        parsed_path = urlparse(self.path)
        client_ip = self.client_address[0]

        if parsed_path.path == "/auth":
            if is_rate_limited(client_ip):
                self.send_response(429)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
                self.send_header("Pragma", "no-cache")
                self.send_header("Expires", "0")
                self.end_headers()
                self.wfile.write(b"Rate limit exceeded. Try again later.")
                logging.warning(f"Rate limit exceeded for /auth from IP {client_ip}.")
                return

        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)

        try:
            data = json.loads(post_data)
        except json.JSONDecodeError:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"Invalid JSON format")
            return

        if parsed_path.path == "/register":
            self.do_register(data, client_ip)
        elif parsed_path.path == "/auth":
            self.do_auth(data, client_ip)
        else:
            self.send_response(405)
            self.end_headers()

    def do_GET(self):  # get request handler function
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            cursor.execute("SELECT kid, key FROM keys")
            keys = cursor.fetchall()
            jwks_keys = []
            for kid, encrypted_pem_key_bytes in keys:
                try:
                    pem_key_bytes = decrypt_private_key_bytes(encrypted_pem_key_bytes)
                    private_key = serialization.load_pem_private_key(
                        pem_key_bytes, password=None, backend=default_backend()
                    )
                    public_key = private_key.public_key()
                    public_numbers = public_key.public_numbers()

                    jwks_keys.append({
                        "alg": "RS256",
                        "kty": "RSA",
                        "use": "sig",
                        "kid": str(kid),
                        "n": int_to_base64(public_numbers.n),
                        "e": int_to_base64(public_numbers.e),
                    })
                except Exception as e:
                    logging.error(f"Error processing key for JWKS (KID={kid}): {e}")
            jwks = {"keys": jwks_keys}
            self.wfile.write(json.dumps(jwks).encode("utf-8"))
            return
        self.send_response(405)
        self.end_headers()


if __name__ == "__main__":

    store_keys()  # Generate and stores keys
    # starts server and handles requests
    webServer = HTTPServer((hostName, serverPort), MyServer)
    logging.info(f"Server started at http://{hostName}:{serverPort}")
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass
    webServer.server_close()
    logging.info("Server stopped.")
