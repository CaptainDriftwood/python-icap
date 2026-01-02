#!/bin/bash

echo "Starting services..."

# Update ClamAV virus definitions (blocking - need definitions before clamd can start)
echo "Updating ClamAV definitions..."
freshclam

# Start ClamAV daemon
echo "Starting ClamAV daemon..."
clamd &
CLAMD_PID=$!

# Wait for ClamAV to be ready (check TCP port)
echo "Waiting for ClamAV to be ready..."
RETRY_COUNT=0
MAX_RETRIES=60
while ! nc -z 127.0.0.1 3310 2>/dev/null; do
    if [ $RETRY_COUNT -ge $MAX_RETRIES ]; then
        echo "Error: ClamAV failed to start after $MAX_RETRIES attempts"
        echo "Checking clamd status..."
        ps aux | grep clam
        exit 1
    fi
    echo "Waiting for ClamAV... attempt $((RETRY_COUNT + 1))/$MAX_RETRIES"
    sleep 2
    RETRY_COUNT=$((RETRY_COUNT + 1))
done
echo "ClamAV is ready"

# Start c-icap server
echo "Starting c-icap server..."
c-icap -N -D -f /etc/c-icap/c-icap.conf
