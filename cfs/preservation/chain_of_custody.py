"""Chain of custody document generator."""

import os
import platform
import socket
from datetime import datetime
from pathlib import Path
from textwrap import dedent

from cfs import __version__
from cfs.types import EvidenceBundle


def generate_chain_of_custody(bundle: EvidenceBundle, output_path: Path) -> Path:
    """Generate chain_of_custody.txt for an evidence bundle.
    
    This document provides a human-readable record of evidence acquisition
    that can be used for legal proceedings and audit purposes.
    
    Args:
        bundle: Evidence bundle containing all artifacts
        output_path: Directory to write chain_of_custody.txt
        
    Returns:
        Path to generated chain of custody file
    """
    now = datetime.utcnow()
    
    content = dedent(f"""\
        ================================================================================
                            CHAIN OF CUSTODY DOCUMENT
        ================================================================================
        
        EVIDENCE COLLECTION RECORD
        --------------------------
        
        Incident ID:        {bundle.incident_id}
        Collection Tool:    Cloud Forensic Snapshot v{__version__}
        Collection Start:   {bundle.collection_start.isoformat()}Z
        Collection End:     {bundle.collection_end.isoformat()}Z
        Document Generated: {now.isoformat()}Z
        
        
        SOURCE INFORMATION
        ------------------
        
        Cloud Provider:     {bundle.provider.value.upper()}
        Account/Project ID: {bundle.account_id}
        Evidence Window:    {bundle.time_window.start_time.isoformat()}Z
                            to {bundle.time_window.end_time.isoformat()}Z
        
        
        COLLECTION ENVIRONMENT
        ----------------------
        
        Hostname:           {bundle.hostname or socket.gethostname()}
        Platform:           {platform.platform()}
        Username:           {os.environ.get('USERNAME', os.environ.get('USER', 'Unknown'))}
        Python Version:     {platform.python_version()}
        Working Directory:  {os.getcwd()}
        
        
        INVESTIGATOR INFORMATION
        ------------------------
        
        Investigator:       {bundle.investigator or "Not specified"}
        Notes:              {bundle.notes or "None"}
        
        
        EVIDENCE SUMMARY
        ----------------
        
        Total Artifacts:    {bundle.total_artifacts}
        Total Size:         {_format_bytes(bundle.total_size_bytes)}
        Output Location:    {bundle.output_path or "Not specified"}
        
        
        ARTIFACT INVENTORY
        ------------------
        
    """)
    
    # Add artifact table
    if bundle.artifacts:
        content += f"{'Name':<40} {'Source':<20} {'SHA-256':<64} {'Size':>12}\n"
        content += "-" * 140 + "\n"
        
        for artifact in bundle.artifacts:
            content += (
                f"{artifact.name:<40} "
                f"{artifact.source:<20} "
                f"{artifact.sha256_hash:<64} "
                f"{_format_bytes(artifact.size_bytes):>12}\n"
            )
    else:
        content += "No artifacts collected.\n"
    
    content += dedent(f"""\
        
        
        INTEGRITY STATEMENT
        -------------------
        
        All artifacts listed above have been verified using SHA-256 cryptographic
        hashing at the time of collection. Hash values are recorded in both this
        document and the accompanying manifest.json file.
        
        Evidence integrity can be verified by comparing computed hashes against
        the recorded values using standard tools (e.g., sha256sum, hashcat).
        
        
        LEGAL NOTICE
        ------------
        
        This document is generated automatically by Cloud Forensic Snapshot.
        It is intended to support forensic investigations and legal proceedings.
        
        The tool performs READ-ONLY operations and does not modify source evidence.
        All evidence is collected via official cloud provider APIs with appropriate
        authentication and authorization.
        
        
        ================================================================================
                                    END OF DOCUMENT
        ================================================================================
    """)
    
    coc_path = output_path / "chain_of_custody.txt"
    coc_path.parent.mkdir(parents=True, exist_ok=True)
    coc_path.write_text(content)
    
    return coc_path


def _format_bytes(size_bytes: int) -> str:
    """Format bytes as human-readable string."""
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} PB"
