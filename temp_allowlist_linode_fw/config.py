import os


class Config:
    """Centralized configuration loaded from environment variables."""

    LINODE_TOKEN = os.environ.get("LINODE_TOKEN", "")
    FIREWALL_ID = os.environ.get("FIREWALL_ID", "")
    ALLOWLIST_INTERVAL_MINUTES = int(
        os.environ.get("ALLOWLIST_INTERVAL_MINUTES", "1440")
    )
    ALLOWLIST_INTERVAL_SECONDS = ALLOWLIST_INTERVAL_MINUTES * 60
    SERVER_PORT = int(os.environ.get("SERVER_PORT", "8080"))
    LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()
    SLOW_OP_THRESHOLD_MS = float(os.environ.get("SLOW_OP_THRESHOLD_MS", "2000.0"))
    TESTING = os.environ.get("TESTING", "").lower() in ("1", "true")

    @classmethod
    def reload(cls):
        """Reload configuration from environment (useful for testing)."""
        cls.LINODE_TOKEN = os.environ.get("LINODE_TOKEN", "")
        cls.FIREWALL_ID = os.environ.get("FIREWALL_ID", "")
        cls.ALLOWLIST_INTERVAL_MINUTES = int(
            os.environ.get("ALLOWLIST_INTERVAL_MINUTES", "1440")
        )
        cls.ALLOWLIST_INTERVAL_SECONDS = cls.ALLOWLIST_INTERVAL_MINUTES * 60
        cls.SERVER_PORT = int(os.environ.get("SERVER_PORT", "8080"))
        cls.LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()
        cls.SLOW_OP_THRESHOLD_MS = float(
            os.environ.get("SLOW_OP_THRESHOLD_MS", "2000.0")
        )
        cls.TESTING = os.environ.get("TESTING", "").lower() in ("1", "true")
