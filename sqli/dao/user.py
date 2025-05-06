import hashlib
import os
import sqlite3
from typing import Dict, List, Optional, Tuple, Union

from sqli.dao.db import get_connection


def get_user_by_username(username: str) -> Optional[Dict]:
    """
    Get user by username
    :param username: username
    :return: user dict or None if user not found
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, password, is_admin FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    if user is None:
        return None
    return {
        "id": user[0],
        "username": user[1],
        "password": user[2],
        "is_admin": bool(user[3]),
    }


def get_user_by_id(user_id: int) -> Optional[Dict]:
    """
    Get user by id
    :param user_id: user id
    :return: user dict or None if user not found
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, password, is_admin FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    if user is None:
        return None
    return {
        "id": user[0],
        "username": user[1],
        "password": user[2],
        "is_admin": bool(user[3]),
    }


def hash_password(password: str) -> str:
    """
    Hash password using scrypt
    :param password: password to hash
    :return: hashed password
    """
    salt = os.urandom(16)
    hash_bytes = hashlib.scrypt(
        password.encode('utf-8'),
        salt=salt,
        n=16384,
        r=8,
        p=1,
        dklen=32
    )
    return salt.hex() + hash_bytes.hex()


def verify_password(stored_password: str, provided_password: str) -> bool:
    """
    Verify password
    :param stored_password: stored password hash
    :param provided_password: provided password
    :return: True if password is correct, False otherwise
    """
    # Check if the stored password is in the old MD5 format (32 hex chars)
    if len(stored_password) == 32:
        # Handle legacy MD5 passwords
        hashed = hashlib.md5(provided_password.encode()).hexdigest()
        return hashed == stored_password
    
    try:
        # Extract salt from stored password (first 32 hex chars = 16 bytes)
        salt_hex = stored_password[:32]
        hash_hex = stored_password[32:]
        
        salt = bytes.fromhex(salt_hex)
        stored_hash = bytes.fromhex(hash_hex)
        
        # Hash the provided password with the same salt
        computed_hash = hashlib.scrypt(
            provided_password.encode('utf-8'),
            salt=salt,
            n=16384,
            r=8,
            p=1,
            dklen=32
        )
        
        # Compare the computed hash with the stored hash
        return computed_hash == stored_hash
    except Exception:
        # If any error occurs (e.g., invalid hex), return False
        return False


def create_user(username: str, password: str, is_admin: bool = False) -> Optional[Dict]:
    """
    Create user
    :param username: username
    :param password: password
    :param is_admin: is admin
    :return: user dict or None if user already exists
    """
    if get_user_by_username(username) is not None:
        return None

    conn = get_connection()
    cursor = conn.cursor()
    hashed_password = hash_password(password)
    cursor.execute(
        "INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)",
        (username, hashed_password, is_admin),
    )
    conn.commit()
    return get_user_by_username(username)


def authenticate_user(username: str, password: str) -> Optional[Dict]:
    """
    Authenticate user
    :param username: username
    :param password: password
    :return: user dict or None if authentication failed
    """
    user = get_user_by_username(username)
    if user is None:
        return None
    if not verify_password(user["password"], password):
        return None
    
    # If using old MD5 hash, upgrade to scrypt
    if len(user["password"]) == 32:
        conn = get_connection()
        cursor = conn.cursor()
        new_hash = hash_password(password)
        cursor.execute(
            "UPDATE users SET password = ? WHERE id = ?",
            (new_hash, user["id"])
        )
        conn.commit()
        user["password"] = new_hash
    
    return user


def get_all_users() -> List[Dict]:
    """
    Get all users
    :return: list of user dicts
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, password, is_admin FROM users")
    users = cursor.fetchall()
    return [
        {
            "id": user[0],
            "username": user[1],
            "password": user[2],
            "is_admin": bool(user[3]),
        }
        for user in users
    ]
