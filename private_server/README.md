# Private Analysis MCP Server

This directory contains the **Private Analysis Layer** for Cloud Forensic Snapshot (CFS).
It is designed to be deployed separately from the acquisition tool, enabling AI-assisted analysis of collected evidence without compromising forensic purity.

## Architecture

*   **Type**: Model Context Protocol (MCP) Server
*   **Transport**: SSE (Server-Sent Events) over HTTP
*   **Infrastructure**: GCP Cloud Run (Serverless Container)
*   **Access**: Read-Only access to CFS output artifacts (e.g., in GCS)

## Deployment on GCP Cloud Run

### 1. Prerequisites
*   GCP Project with Cloud Run API enabled
*   `gcloud` CLI authenticated
*   Collected forensic snapshot uploaded to a GCS bucket (or available locally for testing)

### 2. Build & Deploy
```bash
# Set variables
PROJECT_ID="vulnwatch-vvpok"
SERVICE_NAME="cfs-analysis-layer"
REGION="us-central1"

# Submit build to Cloud Build
gcloud builds submit --tag gcr.io/$PROJECT_ID/$SERVICE_NAME .

# Deploy to Cloud Run
gcloud run deploy $SERVICE_NAME \
  --image gcr.io/$PROJECT_ID/$SERVICE_NAME \
  --platform managed \
  --region $REGION \
  --allow-unauthenticated \
  --set-env-vars SNAPSHOT_PATH="/evidence" 
  # Note: maximizing isolation. For real evidence, mount GCS bucket via Cloud Storage FUSE 
  # or change server.py to read directly from GCS.
```

## Connecting via ADK / Gemini

This server exposes an MCP endpoint. You can connect it to any MCP-compliant client (like Claude Desktop, or a custom Agent built with Google GenAI ADK).

**Tools Exposed:**
*   `list_snapshots()`
*   `read_manifest(path)`
*   `analyze_cloudtrail(path, filters)`
*   `generate_timeline(path)`

## Local Testing

```bash
# Install dependencies
pip install -r requirements.txt

# Run server
fastmcp run server.py
```
