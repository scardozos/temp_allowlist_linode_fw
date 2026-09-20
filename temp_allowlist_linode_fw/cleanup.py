import threading
import time

from linode_api4 import LinodeClient
from linode_api4.objects.networking import Firewall

from temp_allowlist_linode_fw.config import Config
from temp_allowlist_linode_fw.firewall import (
    delete_temporary_firewall_rule,
    get_linode_client,
)
from temp_allowlist_linode_fw.logging import logger

cleanup_started = False
cleanup_lock = threading.Lock()


def periodic_cleanup_loop(
    client: LinodeClient | None = None,
    firewall_id: str | None = None,
    allowlist_interval_seconds: int | None = None,
    check_interval_seconds: int = 300,
):
    """Background loop checking for and removing expired firewall rules.

    Runs periodically every 5 minutes by default.
    """
    logger.debug("Starting periodic firewall cleanup thread...")
    api_client = client or get_linode_client()
    target_fw_id = firewall_id or Config.FIREWALL_ID
    interval_sec = allowlist_interval_seconds or Config.ALLOWLIST_INTERVAL_SECONDS

    while True:
        try:
            firewall = Firewall(api_client, target_fw_id)
            deleted_count = delete_temporary_firewall_rule(
                firewall, allowlist_interval_seconds=interval_sec
            )
            logger.debug(
                "Completed periodic firewall cleanup thread",
                extra={"deleted_count": deleted_count},
            )
        except Exception as e:  # noqa: BLE001
            logger.error(
                f"Error in periodic firewall cleanup: {e}",
                exc_info=True,
                extra={"error": str(e)},
            )
        time.sleep(check_interval_seconds)


def start_periodic_cleanup(
    client: LinodeClient | None = None,
    firewall_id: str | None = None,
    allowlist_interval_seconds: int | None = None,
):
    """Idempotently launch the periodic cleanup thread in the background."""
    global cleanup_started
    if Config.TESTING:
        return

    with cleanup_lock:
        if not cleanup_started:
            thread = threading.Thread(
                target=periodic_cleanup_loop,
                args=(client, firewall_id, allowlist_interval_seconds),
                daemon=True,
            )
            thread.start()
            cleanup_started = True
