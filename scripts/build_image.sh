#!/bin/bash
PROJECT_VERSION=$(grep "version" pyproject.toml | awk -F'"' '{print $2}')
echo "Building temp_allowlist_linode_fw version $PROJECT_VERSION"
sudo docker build . -t "scardozos/temp_allowlist_linode_fw:$PROJECT_VERSION"