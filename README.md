# Linode Firewall Management Flask App

This Flask application manages Linode firewall rules dynamically, allowing HTTP/HTTPS access from a client's IP address for a limited time (default is 10 minutes). The firewall rule is automatically removed after the specified time interval, enhancing security by temporarily allowing access only as needed.

## Features

- **Dynamic Access Control**: Temporarily allows HTTP/HTTPS access to Linode services for the requestor's IP address.
- **Additive Rule Management**: New rules are appended to the existing firewall configuration without overwriting other rules, ensuring co-existence with permanent policies.
- **Automatic Expiration**: Firewall rules are automatically removed after a specified time interval (default: 10 minutes).
- **Selective Cleanup**: Only expires rules created by this application (identified by specific labels), leaving other temporary or permanent rules untouched.
- **Auditable**: Rules include human-readable creation timestamps in their descriptions.
- **Customizable**: Time intervals and settings are configurable via environment variables.
  
## Requirements

- **Python 3.11+**
- **Linode API Token** with permissions to manage networking and firewall settings.
- A **Linode Firewall** created beforehand with a known `firewall_id` with an associated [resource](https://techdocs.akamai.com/cloud-computing/docs/apply-firewall-rules-to-a-service).

---

## Remote Docker Setup and Configuration

### Prerequisites

- **Docker**: Ensure Docker is installed on both your local machine and the remote server.
- **SSH Access**: The remote server must allow SSH access, and you must have a valid SSH key to connect as the root user.
- **rsync**: Ensure `rsync` is installed on both your local machine and the remote server for file transfer.
- **Bash Shell**: The script uses Bash, so make sure your environment supports it.
- **Python Project**: The project version is extracted from `pyproject.toml`, so ensure your project follows this structure.

### Script Arguments

The script requires three arguments to be provided:

1. **IP Address**: The IP address of the remote server.
2. **SSH Key Path**: The path to the SSH private key for connecting to the remote server.
3. **Server Port**: The port on which the server should run.

### Example Usage

```bash
./scripts/deploy_img_in_host.sh 192.168.1.100 /path/to/ssh/key 8080
```

## Makefile Usage

You can automate the build and deploy process using the `make push` command. You must provide the `HOST_IP`, `SSH_KEY`, and `PORT` variables.

### Example

```bash
make push HOST_IP=172.233.115.22 SSH_KEY="/home/scardozo/.ssh/id_ed25519" PORT=8080
```