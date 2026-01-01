#!/bin/bash

echo "Starting services..."

# Update ClamAV virus definitions (in background to not block)
echo "Updating ClamAV definitions..."
freshclam -d &

# Start ClamAV daemon
echo "Starting ClamAV daemon..."
clamd &

# Wait for ClamAV to be ready
sleep 5
echo "Waiting for ClamAV to be ready..."
while ! nc -z localhost 3310; do
    sleep 1
done
echo "ClamAV is ready"

# Start c-icap server
echo "Starting c-icap server..."
c-icap -N -D -f /etc/c-icap/c-icap.conf
