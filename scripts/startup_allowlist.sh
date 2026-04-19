#!/bin/bash


if [ -z "$1" ]; then
    echo "Error: URL argument is required."
    echo "Usage: $0 <url>"
    exit 1
fi

URL="$1"
MAX_RETRIES=10
RETRY_DELAY=10

echo "Starting allowlist update script..."

for ((i=1; i<=MAX_RETRIES; i++)); do
    echo "Attempt $i/$MAX_RETRIES: Requesting access from $URL..."
    
    response=$(curl -s -o /dev/null -w "%{http_code}" "$URL")
    
    if [ "$response" -eq 200 ]; then
        echo "Success! Access granted."
        exit 0
    else
        echo "Failed with HTTP status $response. Retrying in $RETRY_DELAY seconds..."
        sleep $RETRY_DELAY
    fi
done

echo "Error: Could not access $URL after $MAX_RETRIES attempts."
exit 1
