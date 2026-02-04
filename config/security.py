"""
Security configuration and utilities for user authentication.
"""
import hashlib
import secrets


def hash_password(password: str, salt: str = None) -> tuple[str, str]:
    """
    Hash a password using SHA-256 with a salt.
    
    Args:
        password: The plaintext password to hash
        salt: Optional salt value. If not provided, a new salt is generated
        
    Returns:
        A tuple containing (hashed_password, salt)
    """
    if salt is None:
        salt = secrets.token_hex(16)
    
    # Combine password and salt, then hash
    password_salt = f"{password}{salt}"
    hashed = hashlib.sha256(password_salt.encode()).hexdigest()
    
    return hashed, salt


def verify_password(password: str, hashed_password: str, salt: str) -> bool:
    """
    Verify a password against a stored hash.
    
    Args:
        password: The plaintext password to verify
        hashed_password: The stored hash to compare against
        salt: The salt used when creating the hash
        
    Returns:
        True if the password matches, False otherwise
    """
    computed_hash, _ = hash_password(password, salt)
    return computed_hash == hashed_password
