#!/usr/bin/env python3
"""Firewall rule processor for nftfw.

This module processes validated firewall rule records from FirewallReader and
generates nftables commands by executing rule scripts with appropriate environment
variables.

Key Features:
    - Processes records from FirewallReader (incoming.d/outgoing.d rules)
    - Executes rule scripts via RulesReader with environment variables
    - Generates separate IPv4 and IPv6 nftables rules
    - Supports optional IP filtering (rules apply to specific IPs only)
    - Handles port specifications and logging/counting configuration
    - Flushes chains before adding rules for idempotent operation

Environment Variables Passed to Rule Scripts:
    DIRECTION: 'incoming' or 'outgoing'
    TABLE: 'filter' (nftables table name)
    CHAIN: Same as DIRECTION (nftables chain name)
    PROTO: 'ip' or 'ip6' (protocol family)
    IPS: Formatted IP list (single IP or {ip1,ip2,...} set)
    PORTS: Comma-separated port list (optional, if rule has ports)
    COUNTER: 'counter' (optional, if configured)
    LOGGER: 'log prefix "prefix "' (optional, if configured)

Workflow:
    1. Initialize with config, direction, and records from FirewallReader
    2. Call generate() to produce nftables commands
    3. For each record:
       a. Determine which protocols to run (ip, ip6, or both)
       b. Build environment variables for rule script
       c. Execute rule script via RulesReader
       d. Collect generated nftables commands
    4. Return concatenated IPv4 + IPv6 commands

Usage Example:
    >>> from config import Config
    >>> from rulesreader import RulesReader
    >>> from firewallreader import FirewallReader
    >>> cf = Config()
    >>> cf.rulesreader = RulesReader(cf)
    >>> reader = FirewallReader(cf, 'incoming')
    >>> processor = FirewallProcess(cf, 'incoming', reader.records)
    >>> nft_commands = processor.generate()
    >>> print(nft_commands)
    flush chain ip filter incoming
    # Rule: webserver.sh
    add rule ip filter incoming tcp dport 80 accept
    flush chain ip6 filter incoming
    # Rule: webserver.sh
    add rule ip6 filter incoming tcp dport 80 accept

See Also:
    - firewallreader.py: Provides validated rule records
    - rulesreader.py: Executes rule scripts with environment variables
    - fwmanage.py: Orchestrates firewall loading and installation
"""

from __future__ import annotations
from typing import TYPE_CHECKING, cast
import logging
from .ruleserr import RulesReaderError

if TYPE_CHECKING:
    from .config import Config
    from .firewallreader import RecordDict

log = logging.getLogger('nftfw')


class FirewallProcess:
    """Processes firewall rule records to generate nftables commands.

    This class takes validated records from FirewallReader and generates nftables
    commands by executing rule scripts with appropriate environment variables for
    each protocol (IPv4 and IPv6).

    The processing workflow:
        1. Flush existing chains for idempotent operation
        2. For each record, determine applicable protocols
        3. Build environment variables (DIRECTION, PROTO, IPS, PORTS, etc.)
        4. Execute rule script via RulesReader to generate nftables commands
        5. Concatenate IPv4 and IPv6 commands

    Protocol Selection Logic:
        - If record has no IPs: Run for both ip and ip6
        - If record has 'ip' key: Run for ip protocol
        - If record has 'ip6' key: Run for ip6 protocol
        - This allows rules to apply globally or to specific IP lists

    Attributes:
        cf: Config instance providing configuration and RulesReader access
        direction: Either 'incoming' or 'outgoing' for chain selection
        records: List of validated rule records from FirewallReader
        nftconfig: Nft section configuration (counter and logging settings)

    Example:
        >>> from config import Config
        >>> from rulesreader import RulesReader
        >>> from firewallreader import FirewallReader
        >>> cf = Config()
        >>> cf.rulesreader = RulesReader(cf)
        >>> reader = FirewallReader(cf, 'incoming')
        >>> processor = FirewallProcess(cf, 'incoming', reader.records)
        >>> commands = processor.generate()
        >>> # Commands ready for nft execution

    See Also:
        - FirewallReader: Provides validated rule records
        - RulesReader: Executes rule scripts
"""

    def __init__(self, cf: Config, direction: str, records: list[RecordDict]) -> None:
        """Initialize FirewallProcess with configuration and rule records.

        Args:
            cf: Config instance providing configuration and RulesReader access
            direction: Either 'incoming' or 'outgoing' for chain selection
            records: List of validated rule records from FirewallReader

        Example:
            >>> from config import Config
            >>> from rulesreader import RulesReader
            >>> from firewallreader import FirewallReader
            >>> cf = Config()
            >>> cf.rulesreader = RulesReader(cf)
            >>> reader = FirewallReader(cf, 'incoming')
            >>> processor = FirewallProcess(cf, 'incoming', reader.records)
        """
        self.cf: Config = cf
        self.direction: str = direction
        self.records: list[RecordDict] = records
        self.nftconfig: dict[str, str] = cast(dict[str, str], cf.get_ini_values_by_section('Nft'))

    def generate(self) -> str:
        """Generate nftables commands for all records.

        Entry point for command generation. Processes all records and generates
        nftables commands for both IPv4 and IPv6 protocols.

        The output includes:
            1. Chain flush commands for idempotent operation
            2. Generated rules for each record (with comment headers)
            3. IPv4 commands followed by IPv6 commands

        Returns:
            String containing all nftables commands (IPv4 + IPv6 concatenated)

        Example:
            >>> processor = FirewallProcess(cf, 'incoming', records)
            >>> commands = processor.generate()
            >>> print(commands)
            flush chain ip filter incoming
            # Rule: ssh.sh
            add rule ip filter incoming tcp dport 22 accept
            flush chain ip6 filter incoming
            # Rule: ssh.sh
            add rule ip6 filter incoming tcp dport 22 accept
        """
        # lines output at the end of play
        iplines: str = ""
        ip6lines: str = ""

        # Make the sequence of commands re-entrant
        iplines = f"flush chain ip filter {self.direction}\n"
        ip6lines = f"flush chain ip6 filter {self.direction}\n"

        # If we have ips, only run rules for a protocol
        # if there is an ip for the appropriate protocol
        for r in self.records:
            # see if we have specific ips
            haveips: bool = 'ip' in r or 'ip6' in r
            if not haveips or 'ip' in r:
                iplines += self.runforprotocol(r, 'ip')
            if not haveips or 'ip6' in r:
                ip6lines += self.runforprotocol(r, 'ip6')

        return iplines + ip6lines

    def runforprotocol(self, r: RecordDict, proto: str) -> str:
        """Execute rule script for a specific protocol.

        Builds environment variables and executes the rule script via RulesReader
        to generate nftables commands for the specified protocol.

        Environment variables set:
            - DIRECTION: 'incoming' or 'outgoing'
            - TABLE: 'filter'
            - CHAIN: Same as DIRECTION
            - PROTO: 'ip' or 'ip6'
            - IPS: Formatted IP list (if record has IPs for this protocol)
            - PORTS: Comma-separated ports (if record has ports)
            - COUNTER: 'counter' (if configured in Nft section)
            - LOGGER: 'log prefix "prefix "' (if configured in Nft section)

        Args:
            r: Single rule record to process
            proto: Protocol family, either 'ip' (IPv4) or 'ip6' (IPv6)

        Returns:
            String containing nftables commands with comment header, or empty
            string if rule execution fails

        Note:
            Errors from rule execution are logged but don't stop processing.
            This allows other rules to succeed even if one fails.

        Example:
            >>> record = {
            ...     'action': 'ssh',
            ...     'ports': '22',
            ...     'ip': ['192.168.1.100']
            ... }
            >>> commands = processor.runforprotocol(record, 'ip')
            >>> print(commands)
            # Rule: ssh.sh
            add rule ip filter incoming ip saddr 192.168.1.100 tcp dport 22 accept
        """
        # step 1 make the environment
        env: dict[str, str] = {
            'DIRECTION': self.direction,
            'TABLE': 'filter',
            'CHAIN': self.direction
        }

        # set up COUNTER and LOGGING in the environment
        # to make the shell scripts easier
        # LOGGER is formatted as
        # log prefix "<STRING> "
        # note extra space added at the end of the string

        ixc: str = self.direction + "_counter"
        if self.nftconfig[ixc] is not None:
            env['COUNTER'] = 'counter'

        ixh: str = self.direction + "_logging"
        if self.nftconfig[ixh] is not None:
            pref: str = self.nftconfig[ixh]
            env['LOGGER'] = f'log prefix "{pref} "'

        if 'ports' in r:
            env['PORTS'] = r['ports']

        # set up protocol
        env['PROTO'] = proto

        # add ips
        if proto in r.keys():
            env['IPS'] = self.formatips(r[proto])  # type: ignore[literal-required]

        try:
            l: str = f"# Rule: {r['action']}.sh\n"
            l += self.cf.rulesreader.execute(r['action'], env)
            return l
        except RulesReaderError as e:
            log.error(str(e))
            return ""

    @staticmethod
    def formatips(ips: list[str]) -> str:
        """Format IP list for nftables command.

        Formats a list of IPs into nftables syntax:
            - Single IP: Returns the IP as-is (e.g., "192.168.1.1")
            - Multiple IPs: Returns comma-separated set (e.g., "{192.168.1.1,10.0.0.1}")

        Args:
            ips: List of IP addresses or networks as strings

        Returns:
            Formatted string suitable for nftables commands

        Example:
            >>> FirewallProcess.formatips(['192.168.1.1'])
            '192.168.1.1'
            >>> FirewallProcess.formatips(['192.168.1.1', '10.0.0.1'])
            '{192.168.1.1,10.0.0.1}'
            >>> FirewallProcess.formatips(['10.0.0.0/8', '192.168.0.0/16'])
            '{10.0.0.0/8,192.168.0.0/16}'
        """
        if len(ips) == 1:
            return ips[0]
        return '{' + ",".join(ips) + '}'
