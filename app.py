import os
import threading
import time
from datetime import datetime
from flask import Flask, request
from linode_api4 import LinodeClient
from linode_api4.errors import UnexpectedResponseError, ApiError
from linode_api4.objects.networking import Firewall

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


@app.route("/getaccess")
def handle_get():
    # Define the root route that will handle incoming requests
    try:
        return create_temporary_firewall_rule(
            ip_address=request.remote_addr,
            firewall=Firewall(
                client,
                firewall_id
            ),
            allowlist_interval_seconds=allowlist_interval_seconds
        )
    except ApiError as e:
        if getattr(e, "status", 500) == 401:
            return "invalid token", 401
        elif getattr(e, "status", 500) == 403:
            return "permission denied", 403
        else:
            return f"upstream error: {str(e)}", getattr(e, "status", 500)
    except UnexpectedResponseError as e:
        return "Internal error occurred: " + str(e), 500


def gen_firewall_rule_name():
    # Generate a unique name for the temporary
    # firewall rule based on the current unix timestamp
    return f"tmpAllowList_{int(datetime.now().timestamp())}"


def gen_firewall_rule(
    ip_address: str
):
    # Generate a firewall rule to allow inbound traffic
    #  from a specific IP on HTTP/HTTPS ports (80, 443)
    now = datetime.now()
    return {
        'action': 'ACCEPT',
        'addresses': {
            'ipv4': [
                ip_address + "/32"
            ],
        },
        'description': (
            'Allow HTTP out for ' +
            str(int(allowlist_interval_seconds / 60))
            + ' minutes. Created at: ' +
            now.strftime("%Y-%m-%d %H:%M:%S")
        ),
        'label': gen_firewall_rule_name(),
        'ports': '80, 443',
        'protocol': 'TCP'
    }


def is_rule_expired(rule: dict, current_ts: int, allowlist_interval_seconds: int) -> bool:
    # Check if the rule is a temporary allowlist rule
    if not rule.get('label', '').startswith("tmpAllowList_"):
        return False

    parts = rule['label'].split("_")
    if len(parts) < 2:
        return False

    try:
        rule_timestamp = int(parts[1])
        diff = current_ts - rule_timestamp
        return diff >= allowlist_interval_seconds
    except ValueError:
        return False


def build_updated_rules(
    current_rules,
    new_inbound_rules: list
) -> dict:
    outbound_rules = [rule_to_dict(r) for r in current_rules.outbound]
    return {
        "inbound": new_inbound_rules,
        "outbound": outbound_rules,
        "inbound_policy": current_rules.inbound_policy,
        "outbound_policy": current_rules.outbound_policy
    }


def delete_temporary_firewall_rule(
    firewall: Firewall
):
    # Delete the temporary firewall rule only if it has expired
    with firewall_lock:
        current_rules = firewall.rules
        current_ts = int(datetime.now().timestamp())

        new_inbound_rules = []
        any_deleted = False

        for rule_obj in current_rules.inbound:
            rule = rule_to_dict(rule_obj)
            if is_rule_expired(rule, current_ts, allowlist_interval_seconds):
                print(f"Deleting expired rule: {rule.get('label')}")
                any_deleted = True
            else:
                new_inbound_rules.append(rule)

        if any_deleted:
            new_rules = build_updated_rules(current_rules, new_inbound_rules)
            firewall.update_rules(
                rules=new_rules,
            )
            print("Cleaned up expired firewall rules")
        else:
            print("No expired firewall rules to clean up")


def rule_to_dict(rule):
    # Helper to convert a FirewallRule object to a dictionary
    addresses = {}
    if hasattr(rule, 'addresses') and rule.addresses:
        if hasattr(rule.addresses, 'ipv4') and rule.addresses.ipv4:
            addresses['ipv4'] = rule.addresses.ipv4
        if hasattr(rule.addresses, 'ipv6') and rule.addresses.ipv6:
            addresses['ipv6'] = rule.addresses.ipv6

    r = {
        "action": rule.action,
        "protocol": rule.protocol,
        "addresses": addresses,
    }
    if hasattr(rule, 'label') and rule.label:
        r['label'] = rule.label
    if hasattr(rule, 'description') and rule.description:
        r['description'] = rule.description
    if hasattr(rule, 'ports') and rule.ports:
        r['ports'] = rule.ports

    return r


def create_temporary_firewall_rule(
    ip_address: str,
    firewall: Firewall,
    allowlist_interval_seconds: int
):
    # Create a temporary firewall rule,
    # then schedule its deletion after the allowlist interval
    with firewall_lock:
        # Get the current rules
        current_rules = firewall.rules
        current_ts = int(datetime.now().timestamp())

        # Convert existing inbound rules to dicts, filtering out expired ones
        inbound_rules = []
        for rule_obj in current_rules.inbound:
            rule = rule_to_dict(rule_obj)
            if is_rule_expired(rule, current_ts, allowlist_interval_seconds):
                print(f"Cleaning up expired rule on creation: {rule.get('label')}")
            else:
                inbound_rules.append(rule)

        # Append the new rule
        inbound_rules.append(gen_firewall_rule(ip_address))

        new_rules = build_updated_rules(current_rules, inbound_rules)
        firewall.update_rules(
            rules=new_rules,
        )

        timer = threading.Timer(
            allowlist_interval_seconds,
            delete_temporary_firewall_rule,
            [firewall]
        )

        timer.start()

        return (
            "IP allowlisted successfully for "
            + str(int(allowlist_interval_seconds / 60))
            + " minutes"
        )


def periodic_cleanup_loop():
    print("Starting periodic firewall cleanup thread...")
    while True:
        try:
            firewall = Firewall(client, firewall_id)
            delete_temporary_firewall_rule(firewall)
        except Exception as e:
            print(f"Error in periodic firewall cleanup: {e}")
        time.sleep(300)  # check every 5 minutes


def start_periodic_cleanup():
    global cleanup_started
    with cleanup_lock:
        if not cleanup_started:
            thread = threading.Thread(target=periodic_cleanup_loop, daemon=True)
            thread.start()
            cleanup_started = True


@app.before_request
def before_request():
    start_periodic_cleanup()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=server_port)
