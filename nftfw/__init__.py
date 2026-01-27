"""nftfw - Firewall management system for nftables.

This package provides automated firewall management for Linux nftables,
based on the Symbiosis firewall. It offers pattern-based log scanning,
automatic IP blacklisting/whitelisting, and flexible rule management.

Main Features:
    - Automated blacklisting from log file pattern matching
    - Whitelist management from successful login tracking (wtmp)
    - Flexible firewall rule configuration via declarative files
    - Database-backed IP tracking with automatic expiry
    - Support for both IPv4 and IPv6
    - Network blacklist integration (CIDR blocks)
    - GeoIP and DNS blocklist support (optional)

Command-Line Usage:
    Basic commands::

        nftfw load       # Load firewall rules
        nftfw whitelist  # Update whitelist from wtmp
        nftfw blacklist  # Scan logs and update blacklist
        nftfw tidy       # Clean old database entries

    Common options::

        -x, --no-exec     # Test mode, don't install rules
        -f, --full        # Force full install (not just sets)
        -p PATTERN        # Process specific pattern only
        -v, --verbose     # Show information messages
        -q, --quiet       # Suppress console errors
        -o OPTION         # Override config: -o key=value

Actions:
    load:
        Load firewall rules from configuration directories (incoming.d,
        outgoing.d, whitelist.d, blacklist.d). Builds nftables rules,
        tests them, and installs if valid. Uses intelligent set updates
        when only IP lists change.

    whitelist:
        Scan system wtmp file for successful logins and create whitelist
        entries. Helps prevent locking out legitimate users who may
        trigger blacklist rules.

    blacklist:
        Scan log files using patterns from patterns.d directory. Match
        IP addresses against regex patterns, track in database, and
        create blacklist files when thresholds are met. Automatically
        expires old entries.

    tidy:
        Remove database entries older than configured expiry times.
        Typically run daily from cron to maintain database size.

Configuration:
    System files are in /etc/nftfw (configurable via [Locations] sysetc)
    Working files are in /var/lib/nftfw (configurable via [Locations] sysvar)

    Key directories:
        - incoming.d/    Inbound firewall rules
        - outgoing.d/    Outbound firewall rules
        - whitelist.d/   Whitelisted IPs (manual + auto)
        - blacklist.d/   Blacklisted IPs (generated)
        - patterns.d/    Log scanning patterns
        - rule.d/        Shell scripts for rule generation
        - build.d/       Working directory for rule builds

Example:
    Typical workflow::

        # Test firewall configuration
        nftfw -x load

        # Install firewall rules
        nftfw load

        # Update blacklist from logs
        nftfw blacklist

        # Update whitelist from logins
        nftfw whitelist

        # Clean old entries (run from cron)
        nftfw tidy

See Also:
    - config: Configuration management
    - scheduler: Command orchestration
    - blacklist: Blacklist management
    - whitelist: Whitelist management
    - fwmanage: Firewall rule loading

Package Version: 0.9.8
Python Requirement: 3.9+
"""

from __future__ import annotations

import sys

# Version check: nftfw requires Python 3.9+
# Modern type hints and syntax require 3.9 or later
if sys.version_info < (3, 9):
    sys.exit("nftfw requires Python 3.9 or later")

__version__ = "0.9.8"
