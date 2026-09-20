#!/usr/bin/env python3
import logging
import os
import sys
import threading
import time
from contextlib import contextmanager
from datetime import datetime

from flask import Flask, g, has_request_context, request
from linode_api4 import LinodeClient
from linode_api4.errors import ApiError, UnexpectedResponseError
from linode_api4.objects.networking import Firewall
from pythonjsonlogger import jsonlogger


class CustomJsonFormatter(jsonlogger.JsonFormatter):
    def add_fields(self, log_record, record, message_dict):
        super().add_fields(log_record, record, message_dict)
        log_record["logLevel"] = record.levelname
        if "asctime" in log_record:
            log_record["timestamp"] = log_record.pop("asctime")
        for k in ["levelname", "lineno", "funcName", "filename", "module"]:
            log_record.pop(k, None)


def setup_logging():
    log_level_name = os.environ.get("LOG_LEVEL", "INFO").upper()
    log_level = getattr(logging, log_level_name, logging.INFO)

    formatter = CustomJsonFormatter(
        fmt="%(asctime)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ",
    )
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)

    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    root_logger.handlers.clear()
    root_logger.addHandler(handler)

    # Silence noisy 3rd party loggers unless at DEBUG level
    if log_level > logging.DEBUG:
        logging.getLogger("urllib3").setLevel(logging.WARNING)
        logging.getLogger("werkzeug").setLevel(logging.WARNING)
    else:
        logging.getLogger("werkzeug").setLevel(logging.INFO)

    # Disable gunicorn default access log propagation if present
    gunicorn_access = logging.getLogger("gunicorn.access")
    gunicorn_access.handlers.clear()
    gunicorn_access.propagate = False

    return logging.getLogger("temp_allowlist_linode")


logger = setup_logging()


SLOW_OP_THRESHOLD_MS = float(os.environ.get("SLOW_OP_THRESHOLD_MS", "2000.0"))


def record_timing(op_name: str, duration_ms: float):
    if has_request_context() and hasattr(g, "timings") and isinstance(g.timings, dict):
        g.timings[op_name] = round(duration_ms, 2)


@contextmanager
def measure_operation(op_name: str):
    start = time.perf_counter()
    try:
        yield
    finally:
        elapsed = (time.perf_counter() - start) * 1000
        record_timing(op_name, elapsed)
        if elapsed > SLOW_OP_THRESHOLD_MS:
            logger.warning(
                f"Slow operation detected: {op_name} took {elapsed:.2f} ms "
                "(possible upstream rate limiting or API latency)",
                extra={"operation": op_name, "duration_ms": round(elapsed, 2)},
            )


# Initialize Flask application
app = Flask(__name__)

# Load environment variables for authentication and settings
token = os.environ["LINODE_TOKEN"]
client = LinodeClient(token)
allowlist_interval_seconds = int(os.environ["ALLOWLIST_INTERVAL_MINUTES"]) * 60
server_port = os.environ["SERVER_PORT"]
firewall_id = os.environ["FIREWALL_ID"]

# Thread safety locks and flags
firewall_lock = threading.Lock()
cleanup_started = False
cleanup_lock = threading.Lock()


@app.before_request
def before_request():
    g.start_time = time.perf_counter()
    g.timings = {}
    start_periodic_cleanup()


@app.after_request
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


@app.route("/getaccess")
def handle_get():
    # Define the root route that will handle incoming requests
    try:
        return create_temporary_firewall_rule(
            ip_address=request.remote_addr,
            firewall=Firewall(
                client,
                firewall_id,
            ),
            allowlist_interval_seconds=allowlist_interval_seconds,
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


def gen_firewall_rule_name():
    # Generate a unique name for the temporary
    # firewall rule based on the current unix timestamp
    return f"tmpAllowList_{int(datetime.now().timestamp())}"


def gen_firewall_rule(
    ip_address: str,
):
    # Generate a firewall rule to allow inbound traffic
    #  from a specific IP on HTTP/HTTPS ports (80, 443)
    now = datetime.now()
    return {
        "action": "ACCEPT",
        "addresses": {
            "ipv4": [
                ip_address + "/32",
            ],
        },
        "description": (
            "Allow HTTP out for "
            + str(int(allowlist_interval_seconds / 60))
            + " minutes. Created at: "
            + now.strftime("%Y-%m-%d %H:%M:%S")
        ),
        "label": gen_firewall_rule_name(),
        "ports": "80, 443",
        "protocol": "TCP",
    }


def is_rule_expired(
    rule: dict, current_ts: int, allowlist_interval_seconds: int
) -> bool:
    # Check if the rule is a temporary allowlist rule
    if not rule.get("label", "").startswith("tmpAllowList_"):
        return False

    parts = rule["label"].split("_")
    if len(parts) < 2:
        return False

    try:
        rule_timestamp = int(parts[1])
        diff = current_ts - rule_timestamp
        return diff >= allowlist_interval_seconds
    except ValueError:
        return False


def is_temporary_rule_for_ip(rule: dict, ip_address: str) -> bool:
    """Check if the rule is an existing temporary allowlist rule for the IP."""
    if not rule.get("label", "").startswith("tmpAllowList_"):
        return False

    addresses = rule.get("addresses", {})
    ipv4_list = addresses.get("ipv4", [])
    target = f"{ip_address}/32"
    return target in ipv4_list


def build_updated_rules(
    current_rules,
    new_inbound_rules: list,
) -> dict:
    outbound_rules = [rule_to_dict(r) for r in current_rules.outbound]
    return {
        "inbound": new_inbound_rules,
        "outbound": outbound_rules,
        "inbound_policy": current_rules.inbound_policy,
        "outbound_policy": current_rules.outbound_policy,
    }


def delete_temporary_firewall_rule(
    firewall: Firewall,
):
    # Delete the temporary firewall rule only if it has expired
    with firewall_lock:
        current_rules = firewall.rules
        current_ts = int(datetime.now().timestamp())

        new_inbound_rules = []
        deleted_count = 0

        for rule_obj in current_rules.inbound:
            rule = rule_to_dict(rule_obj)
            if is_rule_expired(rule, current_ts, allowlist_interval_seconds):
                logger.info(f"Deleting expired rule: {rule.get('label')}")
                deleted_count += 1
            else:
                new_inbound_rules.append(rule)

        if deleted_count > 0:
            new_rules = build_updated_rules(current_rules, new_inbound_rules)
            firewall.update_rules(
                rules=new_rules,
            )
            logger.info(
                "Cleaned up expired firewall rules",
                extra={"deleted_count": deleted_count},
            )
        else:
            logger.debug("No expired firewall rules to clean up")

        return deleted_count


def rule_to_dict(rule):
    # Helper to convert a FirewallRule object to a dictionary
    addresses = {}
    if hasattr(rule, "addresses") and rule.addresses:
        if hasattr(rule.addresses, "ipv4") and rule.addresses.ipv4:
            addresses["ipv4"] = rule.addresses.ipv4
        if hasattr(rule.addresses, "ipv6") and rule.addresses.ipv6:
            addresses["ipv6"] = rule.addresses.ipv6

    r = {
        "action": rule.action,
        "protocol": rule.protocol,
        "addresses": addresses,
    }
    if hasattr(rule, "label") and rule.label:
        r["label"] = rule.label
    if hasattr(rule, "description") and rule.description:
        r["description"] = rule.description
    if hasattr(rule, "ports") and rule.ports:
        r["ports"] = rule.ports

    return r


def create_temporary_firewall_rule(
    ip_address: str,
    firewall: Firewall,
    allowlist_interval_seconds: int,
):
    """Create or rotate a temporary firewall rule for the specified IP address."""
    lock_start = time.perf_counter()
    with firewall_lock:
        record_timing("acquire_lock_ms", (time.perf_counter() - lock_start) * 1000)

        # Get the current rules
        with measure_operation("fetch_firewall_rules_ms"):
            current_rules = firewall.rules
        current_ts = int(datetime.now().timestamp())

        # Convert existing inbound rules to dicts, filtering out expired ones
        # and rotating any existing temporary rules for this IP address
        with measure_operation("process_rules_ms"):
            inbound_rules = []
            for rule_obj in current_rules.inbound:
                rule = rule_to_dict(rule_obj)
                if is_rule_expired(rule, current_ts, allowlist_interval_seconds):
                    logger.info(
                        f"Cleaning up expired rule on creation: {rule.get('label')}"
                    )
                elif is_temporary_rule_for_ip(rule, ip_address):
                    logger.info(
                        f"Rotating existing temporary rule for {ip_address}: "
                        f"{rule.get('label')}"
                    )
                else:
                    inbound_rules.append(rule)

            # Append the fresh temporary rule for this IP
            inbound_rules.append(gen_firewall_rule(ip_address))

            new_rules = build_updated_rules(current_rules, inbound_rules)

        with measure_operation("update_firewall_rules_ms"):
            firewall.update_rules(
                rules=new_rules,
            )

        with measure_operation("schedule_timer_ms"):
            timer = threading.Timer(
                allowlist_interval_seconds,
                delete_temporary_firewall_rule,
                [firewall],
            )
            timer.start()

        return (
            "IP allowlisted successfully for "
            + str(int(allowlist_interval_seconds / 60))
            + " minutes"
        )


def periodic_cleanup_loop():
    logger.debug("Starting periodic firewall cleanup thread...")
    while True:
        try:
            firewall = Firewall(client, firewall_id)
            deleted_count = delete_temporary_firewall_rule(firewall)
            logger.info(
                "Completed periodic firewall cleanup thread",
                extra={"deleted_count": deleted_count},
            )
        except Exception:
            logger.exception("Error in periodic firewall cleanup")
        time.sleep(300)  # check every 5 minutes


def start_periodic_cleanup():
    global cleanup_started
    if os.environ.get("TESTING", "").lower() in ("1", "true"):
        return
    with cleanup_lock:
        if not cleanup_started:
            thread = threading.Thread(target=periodic_cleanup_loop, daemon=True)
            thread.start()
            cleanup_started = True


# Auto-start cleanup thread on application load
start_periodic_cleanup()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=server_port)
