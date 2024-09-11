#!/bin/bash
# Function to replace all '.' with 'dot' in a given string
replace_dot() {
    local input="$1"
    local output="${input//./dot}"
    echo "$output"
}
# Function to check if the input is a valid IP address
is_valid_ip() {
    local ip=$1
    local valid_ip_regex="^([0-9]{1,3}\.){3}[0-9]{1,3}$"
    if [[ $ip =~ $valid_ip_regex ]]; then
        for octet in $(echo $ip | tr '.' ' '); do
            if ((octet < 0 || octet > 255)); then
                return 1
            fi
        done
        return 0
    else
        return 1
    fi
}

# Check if the first argument is provided
if [ -z "$1" ]; then
    echo "Error: IP address is required as the first argument."
    exit 1
fi

# Check if the first argument is a valid IP address
if ! is_valid_ip "$1"; then
    echo "Error: The first argument must be a valid IP address."
    exit 1
fi

# Check if the second argument is provided
if [ -z "$2" ]; then
    echo "Error: SSH Key Path is required as the second argument."
    exit 1
fi

# Check if the second argument is a valid path
if [ ! -d "$2" ] && [ ! -f "$2" ]; then
    echo "Error: The second argument must be a valid path."
    exit 1
fi

# Check if the third argument is provided
if [ -z "$3" ]; then
    echo "Error: Server Port is required as the first argument."
    exit 1
fi

IP_ADDRESS=$1
SSHKEY_PATH=$2
SERVER_PORT=$3


PROJECT_VERSION=$(grep "version" pyproject.toml | awk -F'"' '{print $2}')
PROJECT_VERSION_NODOT=$(replace_dot "$PROJECT_VERSION")
IMAGE_FILENAME="temp_allowlist_linode_fw_image_$PROJECT_VERSION_NODOT"
_OPTS="-i $SSHKEY_PATH root@$IP_ADDRESS"

echo "Saving temp_allowlist_linode_fw:$PROJECT_VERSION to $(pwd)/$IMAGE_FILENAME"
sudo docker save -o "./$IMAGE_FILENAME" "scardozos/temp_allowlist_linode_fw:$PROJECT_VERSION"
echo "Sending it via rsync to $IP_ADDRESS"
sudo rsync -avz -e "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i $SSHKEY_PATH" --progress "$IMAGE_FILENAME" root@"$IP_ADDRESS":/root/temp_allowlist_linode_fw_root -v
echo "Removing local file ./$IMAGE_FILENAME"
sudo rm "$IMAGE_FILENAME"

ssh $_OPTS sudo bash -s -- < scripts/deploy_img_in_host.sh "$IMAGE_FILENAME" "$PROJECT_VERSION" "$SERVER_PORT"