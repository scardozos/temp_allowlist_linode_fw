import os
import threading
from datetime import datetime
from flask import Flask, request
from linode_api4 import LinodeClient
from linode_api4.errors import UnexpectedResponseError
from linode_api4.objects.networking import Firewall

app = Flask(__name__)
token = os.environ["LINODE_TOKEN"]
client = LinodeClient(token)
allowlist_interval_seconds = int(os.environ["ALLOWLIST_INTERVAL_MINUTES"]) * 60
server_port = os.environ["SERVER_PORT"]
nodebalancer_id = os.environ["NODEBALANCER_ID"]
firewall_id = os.environ["FIREWALL_ID"]


@app.route("/")
def handle_get():
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
    now = datetime.now()
    return (
        "temp_allowlist"
        "_"
        f"{now.hour}.{now.minute}.{now.second}"
        "_"
        f"{now.day}-{now.month}-{now.year}"
    )


def delete_temporary_firewall_rule(
    firewall: Firewall
):
    firewall.update_rules(
        rules=gen_empty_firewall_rule(),
    )
    print("deleted rule successfully")


def gen_empty_firewall_rule():
    return {
        "inbound": [],
        "outbound": [],
        'inbound_policy': 'DROP',
        'outbound_policy': 'ACCEPT'
    }


def gen_firewall_rule(
    ip_address: str
):
    return {
        'inbound': [
            {
                'action': 'ACCEPT',
                'addresses': {
                    'ipv4': [
                        ip_address + "/32"
                    ],
                },
                'description': (
                    'Allow HTTP out for' +
                    str(allowlist_interval_seconds / 60)
                    + 'minutes'
                ),
                'label': gen_firewall_rule_name(),
                'ports': '80,443',
                'protocol': 'TCP'
            }
        ],
        'inbound_policy': 'DROP',
        'outbound_policy': 'ACCEPT'
    }


def create_temporary_firewall_rule(
    ip_address: str,
    firewall: Firewall,
    allowlist_interval_seconds: int
):
    firewall.update_rules(
        rules=gen_firewall_rule(ip_address),
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
