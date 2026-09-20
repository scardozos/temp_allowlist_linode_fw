#!/usr/bin/env python3
"""Backward-compatibility facade for temp_allowlist_linode_fw.

Re-exports core package symbols and provides the WSGI `app` entry point.
"""

import sys
from types import ModuleType

from linode_api4.objects.networking import Firewall

from temp_allowlist_linode_fw import (
    Config,
    CustomJsonFormatter,
    GunicornJsonLogger,
    app,
    build_updated_rules,
    create_app,
    create_temporary_firewall_rule,
    delete_temporary_firewall_rule,
    firewall_lock,
    gen_firewall_rule,
    gen_firewall_rule_name,
    get_linode_client,
    is_rule_expired,
    is_temporary_rule_for_ip,
    logger,
    measure_operation,
    periodic_cleanup_loop,
    record_timing,
    rule_to_dict,
    setup_logging,
    start_periodic_cleanup,
)

# Linode client instance
client = get_linode_client()


class _AppModule(ModuleType):
    """Module wrapper to synchronize mock patches (e.g. @patch('app.Firewall'))."""

    def __setattr__(self, name, value):
        super().__setattr__(name, value)
        if name in ("Firewall", "client"):
            for mod_name in (
                "temp_allowlist_linode_fw.app",
                "temp_allowlist_linode_fw.firewall",
                "temp_allowlist_linode_fw.cleanup",
            ):
                if mod_name in sys.modules:
                    setattr(sys.modules[mod_name], name, value)


sys.modules[__name__].__class__ = _AppModule

__all__ = [
    "Config",
    "CustomJsonFormatter",
    "Firewall",
    "GunicornJsonLogger",
    "app",
    "build_updated_rules",
    "client",
    "create_app",
    "create_temporary_firewall_rule",
    "delete_temporary_firewall_rule",
    "firewall_lock",
    "gen_firewall_rule",
    "gen_firewall_rule_name",
    "get_linode_client",
    "is_rule_expired",
    "is_temporary_rule_for_ip",
    "logger",
    "measure_operation",
    "periodic_cleanup_loop",
    "record_timing",
    "rule_to_dict",
    "setup_logging",
    "start_periodic_cleanup",
]

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=Config.SERVER_PORT)
