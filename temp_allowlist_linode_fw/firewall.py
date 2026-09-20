import threading
import time
from datetime import datetime

from linode_api4 import LinodeClient
from linode_api4.objects.networking import Firewall

from temp_allowlist_linode_fw.config import Config
from temp_allowlist_linode_fw.logging import (
    logger,
    measure_operation,
    record_timing,
)

# Concurrency lock for firewall modifications
firewall_lock = threading.Lock()


def get_linode_client(token: str | None = None) -> LinodeClient:
    """Create and return a LinodeClient instance."""
    auth_token = token or Config.LINODE_TOKEN
    return LinodeClient(auth_token)


def gen_firewall_rule_name() -> str:
    """Generate a unique label for the temporary rule based on timestamp."""
    return f"tmpAllowList_{int(datetime.now().timestamp())}"


def gen_firewall_rule(
    ip_address: str,
    allowlist_interval_seconds: int | None = None,
) -> dict:
    """Generate a firewall rule allowing inbound HTTP/HTTPS traffic from target IP."""
    if allowlist_interval_seconds is None:
        allowlist_interval_seconds = Config.ALLOWLIST_INTERVAL_SECONDS

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
    rule: dict,
    current_ts: int,
    allowlist_interval_seconds: int | None = None,
) -> bool:
    """Check whether a temporary allowlist rule has exceeded its TTL."""
    if allowlist_interval_seconds is None:
        allowlist_interval_seconds = Config.ALLOWLIST_INTERVAL_SECONDS

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


def rule_to_dict(rule) -> dict:
    """Convert a FirewallRule object or dict representation to a standard dictionary."""
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


def build_updated_rules(current_rules, new_inbound_rules: list) -> dict:
    """Construct a payload for firewall.update_rules preserving outbound settings."""
    outbound_rules = [rule_to_dict(r) for r in current_rules.outbound]
    return {
        "inbound": new_inbound_rules,
        "outbound": outbound_rules,
        "inbound_policy": current_rules.inbound_policy,
        "outbound_policy": current_rules.outbound_policy,
    }


def delete_temporary_firewall_rule(
    firewall: Firewall,
    allowlist_interval_seconds: int | None = None,
) -> int:
    """Delete expired temporary firewall rules. Emits DEBUG logs and catches errors."""
    if allowlist_interval_seconds is None:
        allowlist_interval_seconds = Config.ALLOWLIST_INTERVAL_SECONDS

    with firewall_lock:
        try:
            current_rules = firewall.rules
            current_ts = int(datetime.now().timestamp())

            new_inbound_rules = []
            deleted_count = 0

            for rule_obj in current_rules.inbound:
                rule = rule_to_dict(rule_obj)
                if is_rule_expired(rule, current_ts, allowlist_interval_seconds):
                    logger.debug(f"Deleting expired rule: {rule.get('label')}")
                    deleted_count += 1
                else:
                    new_inbound_rules.append(rule)

            if deleted_count > 0:
                new_rules = build_updated_rules(current_rules, new_inbound_rules)
                firewall.update_rules(rules=new_rules)
                logger.debug(
                    "Cleaned up expired firewall rules",
                    extra={"deleted_count": deleted_count},
                )
            else:
                logger.debug("No expired firewall rules to clean up")

            return deleted_count
        except Exception as e:  # noqa: BLE001
            logger.error(
                f"Failed to clean up expired firewall rules: {e}",
                exc_info=True,
                extra={"error": str(e)},
            )
            return 0


def create_temporary_firewall_rule(
    ip_address: str,
    firewall: Firewall,
    allowlist_interval_seconds: int | None = None,
) -> str:
    """Create or rotate a temporary allowlist firewall rule for the specified IP."""
    if allowlist_interval_seconds is None:
        allowlist_interval_seconds = Config.ALLOWLIST_INTERVAL_SECONDS

    lock_start = time.perf_counter()
    with firewall_lock:
        record_timing("acquire_lock_ms", (time.perf_counter() - lock_start) * 1000)

        # Get the current rules
        with measure_operation("fetch_firewall_rules_ms"):
            current_rules = firewall.rules
        current_ts = int(datetime.now().timestamp())

        # Convert existing inbound rules to dicts, filtering expired rules
        # and rotating existing rules for this IP address
        with measure_operation("process_rules_ms"):
            inbound_rules = []
            for rule_obj in current_rules.inbound:
                rule = rule_to_dict(rule_obj)
                if is_rule_expired(rule, current_ts, allowlist_interval_seconds):
                    logger.info(
                        f"Cleaning up expired rule on creation: {rule.get('label')}"
                    )
                elif is_temporary_rule_for_ip(rule, ip_address):
                    ipv4_list = rule.get("addresses", {}).get("ipv4", [])
                    rule_ips_str = ", ".join(ipv4_list)
                    target = f"{ip_address}/32"

                    if len(ipv4_list) > 1:
                        rule["addresses"]["ipv4"].remove(target)
                        inbound_rules.append(rule)
                        logger.info(
                            f"Removed {ip_address} from shared temporary rule "
                            f"(remaining: {', '.join(rule['addresses']['ipv4'])}): "
                            f"{rule.get('label')}"
                        )
                    else:
                        logger.info(
                            "Rotating existing temporary rule "
                            f"(contained {rule_ips_str}) "
                            f"for {ip_address}: {rule.get('label')}"
                        )
                else:
                    inbound_rules.append(rule)

            # Append the fresh temporary rule for this IP
            inbound_rules.append(
                gen_firewall_rule(ip_address, allowlist_interval_seconds)
            )

            new_rules = build_updated_rules(current_rules, inbound_rules)

        with measure_operation("update_firewall_rules_ms"):
            firewall.update_rules(rules=new_rules)

        with measure_operation("schedule_timer_ms"):
            timer = threading.Timer(
                allowlist_interval_seconds,
                delete_temporary_firewall_rule,
                [firewall, allowlist_interval_seconds],
            )
            timer.start()

        return (
            "IP allowlisted successfully for "
            + str(int(allowlist_interval_seconds / 60))
            + " minutes"
        )
