"""SHA-256 hashing utilities for evidence integrity."""

import hashlib
from pathlib import Path
from typing import BinaryIO


HASH_ALGORITHM = "sha256"
BUFFER_SIZE = 65536  # 64KB chunks for memory efficiency


def compute_sha256(file_path: Path) -> str:
    """Compute SHA-256 hash of a file.
    
    Args:
        file_path: Path to the file to hash
        
    Returns:
        Lowercase hexadecimal SHA-256 hash string
        
    Raises:
        FileNotFoundError: If file doesn't exist
        PermissionError: If file can't be read
    """
    sha256_hash = hashlib.sha256()
    
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(BUFFER_SIZE), b""):
            sha256_hash.update(chunk)
    
    return sha256_hash.hexdigest()


def compute_sha256_stream(stream: BinaryIO) -> str:
    """Compute SHA-256 hash from a binary stream.
    
    Args:
        stream: Binary file-like object
        
    Returns:
        Lowercase hexadecimal SHA-256 hash string
    """
    sha256_hash = hashlib.sha256()
    
    for chunk in iter(lambda: stream.read(BUFFER_SIZE), b""):
        sha256_hash.update(chunk)
    
    return sha256_hash.hexdigest()


def compute_sha256_bytes(data: bytes) -> str:
    """Compute SHA-256 hash of bytes.
    
    Args:
        data: Bytes to hash
        
    Returns:
        Lowercase hexadecimal SHA-256 hash string
    """
    return hashlib.sha256(data).hexdigest()


def verify_hash(file_path: Path, expected_hash: str) -> bool:
    """Verify a file against an expected SHA-256 hash.
    
    Args:
        file_path: Path to the file to verify
        expected_hash: Expected SHA-256 hash (case-insensitive)
        
    Returns:
        True if hash matches, False otherwise
    """
    actual_hash = compute_sha256(file_path)
    return actual_hash.lower() == expected_hash.lower()


def generate_hash_file(artifacts: list[tuple[Path, str]], output_path: Path) -> None:
    """Generate a sha256sums.txt compatible hash file.
    
    Args:
        artifacts: List of (file_path, hash) tuples
        output_path: Path to write the hash file
    """
    lines = []
    for file_path, file_hash in artifacts:
        # Use relative path for portability
        lines.append(f"{file_hash}  {file_path.name}")
    
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines) + "\n")
