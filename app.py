import os
import threading
from datetime import datetime
from flask import Flask, request
from linode_api4 import LinodeClient
from linode_api4.errors import UnexpectedResponseError
from linode_api4.objects.networking import Firewall

# Initialize Flask application
app = Flask(__name__)

# Load environment variables for authentication and settings
token = os.environ["LINODE_TOKEN"]
client = LinodeClient(token)
allowlist_interval_seconds = int(os.environ["ALLOWLIST_INTERVAL_MINUTES"]) * 60
server_port = os.environ["SERVER_PORT"]
firewall_id = os.environ["FIREWALL_ID"]


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
    except UnexpectedResponseError as e:
        return "Internal error occurred: " + e, 500


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
            str(allowlist_interval_seconds / 60)
            + ' minutes. Created at: ' +
            now.strftime("%Y-%m-%d %H:%M:%S")
        ),
        'label': gen_firewall_rule_name(),
        'ports': '80, 443',
        'protocol': 'TCP'
    }


def delete_temporary_firewall_rule(
    firewall: Firewall
):
    # Delete the temporary firewall rule only if it has expired
    current_rules = firewall.rules
    inbound_rules = current_rules.inbound

    # Current time
    now = datetime.now()

    new_inbound_rules = []

    for rule_obj in inbound_rules:
        # Convert object to dict to safely access fields and modify
        rule = rule_to_dict(rule_obj)

        # Check if the rule is a temporary allowlist rule
        if rule.get('label', '').startswith("tmpAllowList_"):
            parts = rule['label'].split("_")
            if len(parts) >= 2:
                try:
                    rule_timestamp = int(parts[1])

                    # Calculate difference in seconds
                    # We use timestamp() to compare with unix timestamp
                    current_ts = int(now.timestamp())
                    diff = current_ts - rule_timestamp

                    if diff < allowlist_interval_seconds:
                        # Rule is still valid, keep it
                        new_inbound_rules.append(rule)
                    else:
                        print(f"Deleting expired rule: {rule.get('label')}")
                except ValueError:
                    # If parsing fails, keep the rule to be safe
                    new_inbound_rules.append(rule)
            else:
                new_inbound_rules.append(rule)
        else:
            # Keep non-temporary rules
            new_inbound_rules.append(rule)

    # Prepare the rules dict for update
    # We need to preserve outbound rules as well
    outbound_rules = [rule_to_dict(r) for r in current_rules.outbound]

    new_rules = {
        "inbound": new_inbound_rules,
        "outbound": outbound_rules,
        "inbound_policy": current_rules.inbound_policy,
        "outbound_policy": current_rules.outbound_policy
    }

    firewall.update_rules(
        rules=new_rules,
    )
    print("Cleaned up firewall rules")


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

    # Get the current rules
    current_rules = firewall.rules

    # Convert existing inbound rules to dicts
    inbound_rules = [rule_to_dict(r) for r in current_rules.inbound]

    # Append the new rule
    inbound_rules.append(gen_firewall_rule(ip_address))

    # Preserve outbound rules
    outbound_rules = [rule_to_dict(r) for r in current_rules.outbound]

    new_rules = {
        "inbound": inbound_rules,
        "outbound": outbound_rules,
        "inbound_policy": current_rules.inbound_policy,
        "outbound_policy": current_rules.outbound_policy
    }

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
        + str(allowlist_interval_seconds / 60)
        + "minutes"
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=server_port)
