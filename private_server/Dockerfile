# Use official Python runtime
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy server code
COPY server.py .

# Expose port (Cloud Run defaults to 8080)
ENV PORT=8080

# Run the FastMCP server in SSE mode (default for run unless specified otherwise, but we make sure)
# FastMCP 'run' usually detects env or args. For production SSE:
CMD ["fastmcp", "run", "server.py", "--transport", "sse", "--port", "8080", "--host", "0.0.0.0"]
