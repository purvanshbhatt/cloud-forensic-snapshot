"""Private MCP Server for Cloud Forensic Snapshot analysis.

This server is DEPLOYED SEPARATELY from the public CLI and provides
AI-assisted analysis tools for collected evidence bundles.

Author: Self (Private)
Design: FastMCP based, read-only access to 'forensic_snapshot'
"""

import json
from pathlib import Path
from typing import Any

from fastmcp import FastMCP

# Initialize FastMCP
mcp = FastMCP("cfs-analysis")

# Configuration
SNAPSHOT_DIR = Path("./forensic_snapshot").resolve()


@mcp.tool()
def list_snapshots() -> list[str]:
    """List available forensic snapshots in the workspace.
    
    Returns:
        List of snapshot directory names.
    """
    if not SNAPSHOT_DIR.exists():
        return []
    
    # Snapshots are typically provider/account_id or just organized by folder
    # We look for folders containing a manifest.json
    snapshots = []
    for manifest in SNAPSHOT_DIR.rglob("manifest.json"):
        # Return path relative to snapshot dir
        snapshots.append(str(manifest.parent.relative_to(SNAPSHOT_DIR)))
    return snapshots


@mcp.tool()
def read_manifest(snapshot_path: str) -> dict[str, Any]:
    """Read the manifest.json for a specific snapshot.
    
    Args:
        snapshot_path: Relative path to the snapshot folder (from list_snapshots)
    """
    target = SNAPSHOT_DIR / snapshot_path / "manifest.json"
    if not target.exists():
        return {"error": f"Manifest not found at {snapshot_path}"}
    
    try:
        with open(target, "r") as f:
            return json.load(f)
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
def get_chain_of_custody(snapshot_path: str) -> str:
    """Read the chain_of_custody.txt for a snapshot."""
    target = SNAPSHOT_DIR / snapshot_path / "chain_of_custody.txt"
    if not target.exists():
        return "Chain of custody file not found."
    
    return target.read_text(encoding="utf-8")


@mcp.tool()
def analyze_cloudtrail(snapshot_path: str, filter_event: str = "", filter_user: str = "") -> list[dict[str, Any]]:
    """Query CloudTrail events from a snapshot.
    
    Args:
        snapshot_path: Relative path to snapshot
        filter_event: Optional substring to match event names
        filter_user: Optional substring to match user identity
        
    Returns:
        List of matching events (max 50)
    """
    # Locate cloudtrail file (typical path pattern)
    # Recursively find events.json in aws/cloudtrail
    base_path = SNAPSHOT_DIR / snapshot_path
    events_files = list(base_path.rglob("events.json"))
    
    if not events_files:
        return [{"error": "No CloudTrail events.json found in snapshot"}]
    
    results = []
    
    for ef in events_files:
        try:
            with open(ef, "r") as f:
                events = json.load(f)
                
            for event in events:
                # Basic filtering
                evt_name = event.get("EventName", "")
                username = event.get("Username", "") or event.get("CloudTrailEvent", {}).get("userIdentity", {}).get("userName", "")
                
                if filter_event and filter_event.lower() not in evt_name.lower():
                    continue
                if filter_user and filter_user.lower() not in username.lower():
                    continue
                    
                results.append(event)
        except Exception:
            continue
            
    return results[:50]


@mcp.tool()
def generate_timeline(snapshot_path: str) -> str:
    """Generate a high-level timeline of all collected events.
    
    Aggregates timestamps from CloudTrail, Azure Activity, and GCP Audit logs.
    """
    base_path = SNAPSHOT_DIR / snapshot_path
    timeline = []
    
    # helper
    def add_event(ts, source, desc):
        if ts:
            timeline.append({"timestamp": ts, "source": source, "description": desc})
            
    # CloudTrail
    for ef in base_path.rglob("events.json"): # AWS
        try:
            data = json.load(open(ef))
            for e in data:
                add_event(e.get("EventTime"), "AWS", f"{e.get('EventName')} by {e.get('Username')}")
        except: pass

    # Azure Activity
    for af in base_path.rglob("activity_logs.json"): # Azure
        try:
            data = json.load(open(af))
            for e in data:
                # Azure keys differ slightly
                ts = e.get("event_timestamp") or e.get("eventTimestamp")
                name = e.get("operation_name") or e.get("operationName", {}).get("localizedValue")
                add_event(ts, "Azure", name)
        except: pass

    # GCP Audit
    for gf in base_path.rglob("audit_logs.json"): # GCP
        try:
            data = json.load(open(gf))
            for e in data:
                ts = e.get("timestamp")
                method = e.get("protoPayload", {}).get("methodName", "Unknown")
                principal = e.get("protoPayload", {}).get("authenticationInfo", {}).get("principalEmail", "Unknown")
                add_event(ts, "GCP", f"{method} by {principal}")
        except: pass

    # Sort
    timeline.sort(key=lambda x: x["timestamp"] or "")
    
    # Format
    output = ["# Combined Forensic Timeline", ""]
    for t in timeline:
        output.append(f"- {t['timestamp']} [{t['source']}] {t['description']}")
        
    return "\n".join(output)


if __name__ == "__main__":
    mcp.run()
