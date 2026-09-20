import logging
import time

from flask import Flask, g, request
from linode_api4.errors import ApiError, UnexpectedResponseError
from linode_api4.objects.networking import Firewall

from temp_allowlist_linode_fw.cleanup import start_periodic_cleanup
from temp_allowlist_linode_fw.config import Config
from temp_allowlist_linode_fw.firewall import (
    create_temporary_firewall_rule,
    get_linode_client,
)
from temp_allowlist_linode_fw.logging import logger


def create_app(config_class=None) -> Flask:
    """Application factory for temp_allowlist_linode_fw."""
    flask_app = Flask(__name__)

    @flask_app.before_request
    def before_request():
        g.start_time = time.perf_counter()
        g.timings = {}
        start_periodic_cleanup()

    @flask_app.after_request
    def after_request(response):
        is_available_route = request.url_rule is not None
        # Log access for available routes, or for all routes if DEBUG level is enabled
        if is_available_route or logger.isEnabledFor(logging.DEBUG):
            duration_ms = round((time.perf_counter() - g.start_time) * 1000, 2)
            extra_data = {
                "method": request.method,
                "path": request.path,
                "status_code": response.status_code,
                "remote_addr": request.remote_addr,
                "duration_ms": duration_ms,
            }
            if hasattr(g, "timings") and g.timings:
                extra_data["operations"] = g.timings

            log_msg = f"{request.method} {request.path} {response.status_code}"
            if is_available_route:
                logger.info(log_msg, extra=extra_data)
            else:
                logger.debug(log_msg, extra=extra_data)
        return response

    @flask_app.route("/getaccess")
    def handle_get():
        try:
            client = get_linode_client()
            return create_temporary_firewall_rule(
                ip_address=request.remote_addr,
                firewall=Firewall(client, Config.FIREWALL_ID),
                allowlist_interval_seconds=Config.ALLOWLIST_INTERVAL_SECONDS,
            )
        except ApiError as e:
            status_code = getattr(e, "status", 500)
            logger.error(f"Linode API error: {e}")
            if status_code == 401:
                return "invalid token", 401
            elif status_code == 403:
                return "permission denied", 403
            else:
                return f"upstream error: {e!s}", status_code
        except UnexpectedResponseError as e:
            logger.exception("Internal error occurred")
            return "Internal error occurred: " + str(e), 500

    return flask_app


# Default application instance for WSGI servers
app = create_app()
