"""Evidence preservation subpackage."""

from cfs.preservation.hashing import compute_sha256, compute_sha256_stream, verify_hash
from cfs.preservation.manifest import generate_manifest
from cfs.preservation.chain_of_custody import generate_chain_of_custody
from cfs.preservation.immutability import check_immutability, ImmutabilityStatus

__all__ = [
    "compute_sha256",
    "compute_sha256_stream", 
    "verify_hash",
    "generate_manifest",
    "generate_chain_of_custody",
    "check_immutability",
    "ImmutabilityStatus",
]
