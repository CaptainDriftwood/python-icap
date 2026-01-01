#!/bin/bash

echo "Starting services..."

# Update ClamAV virus definitions (in background to not block)
echo "Updating ClamAV definitions..."
freshclam &
FRESHCLAM_PID=$!

# Start ClamAV daemon
echo "Starting ClamAV daemon..."
clamd &
CLAMD_PID=$!

# Wait for ClamAV to be ready
sleep 5
echo "Waiting for ClamAV to be ready..."
RETRY_COUNT=0
MAX_RETRIES=30
while ! nc -z localhost 3310; do
    if [ $RETRY_COUNT -ge $MAX_RETRIES ]; then
        echo "Error: ClamAV failed to start after $MAX_RETRIES attempts"
        exit 1
    fi
    sleep 1
    RETRY_COUNT=$((RETRY_COUNT + 1))
done
echo "ClamAV is ready"

# Start c-icap server
echo "Starting c-icap server..."
c-icap -N -D -f /etc/c-icap/c-icap.conf
