# Linode Firewall Management Flask App

This Flask application manages Linode firewall rules dynamically, allowing HTTP/HTTPS access from a client's IP address for a limited time (default is 10 minutes). The firewall rule is automatically removed after the specified time interval, enhancing security by temporarily allowing access only as needed.

## Features

- Temporarily allow access to Linode services for the IP address accessing the Flask app.
- Automatically remove firewall rules after a specified time interval.
- Customizable time intervals and settings via environment variables.
  
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