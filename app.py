#!/usr/bin/env python3
"""Entry point for temp_allowlist_linode_fw."""

from temp_allowlist_linode_fw.app import app
from temp_allowlist_linode_fw.config import Config

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=Config.SERVER_PORT)
