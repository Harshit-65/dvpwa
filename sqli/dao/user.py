import os
import hashlib
import sqlite3
from typing import Dict, List, Optional, Any

from sqli.dao.base import BaseDao


class UserDao(BaseDao):
    def __init__(self, connection_string):
        super(UserDao, self).__init__(connection_string)

    def hash_password(self, password):
        salt = os.urandom(16)  # Generate a random 16-byte salt
        hash_result = hashlib.scrypt(
            password.encode(),
            salt=salt,
            n=16384,  # CPU/memory cost parameter
            r=8,      # Block size parameter
            p=1,      # Parallelization parameter
            dklen=32  # Output length
        )
        # Store both the salt and the hash result
        return salt.hex() + '$' + hash_result.hex()

    def verify_password(self, stored_password, provided_password):
        # Split the stored password into salt and hash
        salt_hex, hash_hex = stored_password.split('$')
        salt = bytes.fromhex(salt_hex)
        
        # Hash the provided password with the same salt
        calculated_hash = hashlib.scrypt(
            provided_password.encode(),
            salt=salt,
            n=16384,
            r=8,
            p=1,
            dklen=32
        )
        
        # Compare the calculated hash with the stored hash
        return calculated_hash.hex() == hash_hex

    def get_user_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        conn = sqlite3.connect(self.connection_string)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        conn.close()

        if row:
            return dict(row)
        return None

    def get_user_by_id(self, user_id: int) -> Optional[Dict[str, Any]]:
        conn = sqlite3.connect(self.connection_string)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        row = cursor.fetchone()
        conn.close()

        if row:
            return dict(row)
        return None

    def create_user(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        conn = sqlite3.connect(self.connection_string)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Check if user already exists
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            conn.close()
            return None

        # Create new user
        cursor.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            (username, self.hash_password(password))
        )
        conn.commit()

        # Get the newly created user
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        conn.close()

        if row:
            return dict(row)
        return None

    def authenticate(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        user = self.get_user_by_username(username)
        if not user:
            return None

        if self.verify_password(user["password"], password):
            return user
        return None
