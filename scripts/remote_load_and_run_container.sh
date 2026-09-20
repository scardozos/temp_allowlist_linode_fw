#!/bin/bash
# ==============================================================================
# Script: remote_load_and_run_container.sh
#
# Description:
#   Runs on the remote destination host (streamed via SSH from
#   deploy_to_remote_host.sh). Loads the transferred Docker image archive,
#   stops/removes any existing temp_allowlist_linode_fw container, and launches
#   the newly updated container.
#
# Expected Arguments:
#   $1 - IMAGE_FILENAME : Transferred Docker image archive file (e.g. temp_allowlist_linode_fw_image_v0dot4)
#   $2 - VERSION_ID     : Docker image version tag (e.g. v0.4)
#   $3 - SERVER_PORT    : Host/container port to bind (e.g. 8080)
#
# Example Usage:
#   ./scripts/remote_load_and_run_container.sh temp_allowlist_linode_fw_image_v0dot4 v0.4 8080
#   ssh -i ~/.ssh/id_ed25519 root@<IP> sudo bash -s -- < scripts/remote_load_and_run_container.sh image_name v0.4 8080
# ==============================================================================
set -o nounset

# Check if the first argument is provided
if [ -z "$1" ]; then
    echo "Error: Image filename is required as the first argument."
    exit 1
fi

# Check if the second argument is provided
if [ -z "$2" ]; then
    echo "Error: Version ID is required as the second argument."
    exit 1
fi

# Check if the third argument is provided
if [ -z "$3" ]; then
    echo "Error: Server Port is required as the third argument."
    exit 1
fi

IMAGE_FILENAME=$1
VERSION_ID=$2
SERVER_PORT=$3
# shellcheck disable=SC2164
cd /root/temp_allowlist_linode_fw_root
docker load -i "$IMAGE_FILENAME"
echo "Checking if temp_allowlist_linode_fw is already running"
# Run the docker command and capture the output
output=$(docker ps -aqf name=temp_allowlist_linode_fw)

# Check if the output is empty
if [ -n "$output" ]; then
    echo "Containers with name 'temp_allowlist_linode_fw' found, killing and removing them accordingly"
    docker kill temp_allowlist_linode_fw
    docker rm temp_allowlist_linode_fw
else
    echo "No containers with name 'temp_allowlist_linode_fw' found."
fi
echo "Running new version $VERSION_ID of temp_allowlist_linode_fw"
docker run -p "$SERVER_PORT:$SERVER_PORT" -d --name temp_allowlist_linode_fw scardozos/temp_allowlist_linode_fw:"$VERSION_ID"