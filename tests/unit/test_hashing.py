"""Unit tests for hashing utilities."""

import hashlib
import tempfile
from pathlib import Path
from cfs.preservation.hashing import compute_sha256, verify_hash

def test_compute_sha256_string():
    """Test SHA256 computation for a known string."""
    content = b"cloud forensics"
    # echo -n "cloud forensics" | sha256sum
    expected = "3472099352723005085a6989410103750058e17812547e0909673981882d9263"
    
    with tempfile.NamedTemporaryFile() as f:
        f.write(content)
        f.flush()
        f.seek(0)
        
        result = compute_sha256(Path(f.name))
        assert result == expected

def test_verify_hash_valid():
    """Test hash verification returns True for valid hash."""
    content = b"integrity check"
    with tempfile.NamedTemporaryFile() as f:
        f.write(content)
        f.flush()
        f.seek(0)
        
        computed = compute_sha256(Path(f.name))
        assert verify_hash(Path(f.name), computed) is True

def test_verify_hash_invalid():
    """Test hash verification returns False for invalid hash."""
    content = b"integrity check"
    with tempfile.NamedTemporaryFile() as f:
        f.write(content)
        f.flush()
        f.seek(0)
        
        assert verify_hash(Path(f.name), "deadbeef") is False
