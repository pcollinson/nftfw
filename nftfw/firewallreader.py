"""Firewall rule file reader for nftfw.

This module reads and validates firewall rule files from incoming.d and outgoing.d
directories, creating structured records for processing by firewallprocess.py.

Key Features:
    - Reads numbered rule files (nn-action format) from incoming.d/outgoing.d
    - Validates rule actions using RulesReader, port numbers, or service names
    - Validates IP addresses, networks (CIDR notation), and hostnames in rule contents
    - Resolves hostnames to IPv4/IPv6 addresses via DNS
    - Maintains execution order based on file numbering
    - Separates IPv4 and IPv6 addresses for protocol-specific processing

File Naming Convention:
    Files must follow the pattern: nn-action
    - nn: Two-digit number (00-99) determining execution order
    - action: Rule name, port number, or service name

    Examples:
        10-webserver    → Uses 'webserver' rule from rule.d
        20-ssh          → Uses 'ssh' service (port 22)
        30-8080         → Uses port 8080 directly

File Contents (optional):
    Each file can contain IP addresses, networks, or hostnames (one per line):
    - IPv4: 192.168.1.1 or 192.168.1.0/24
    - IPv6: 2001:db8::1 or 2001:db8::/32
    - Hostnames: example.com (resolved via DNS)

    Example file contents:
        192.168.1.100
        10.0.0.0/8
        2001:db8::1
        example.com

Workflow:
    1. Scan directory for files matching nn-action pattern
    2. Read file contents and create initial records
    3. Validate action (rule name, port, or service lookup)
    4. Validate contents (IP addresses, networks, hostnames)
    5. Resolve hostnames to IP addresses via DNS
    6. Separate IPv4 and IPv6 addresses
    7. Return ordered list of validated records

Usage Example:
    >>> from config import Config
    >>> cf = Config()
    >>> # RulesReader must be loaded first (done by fwmanage.py)
    >>> reader = FirewallReader(cf, 'incoming')
    >>> for rec in reader.records:
    ...     print(f"Action: {rec['action']}, IPs: {rec.get('ip', [])}")
    Action: webserver, IPs: ['192.168.1.100', '192.168.1.0/24']

See Also:
    - firewallprocess.py: Processes records to generate nftables commands
    - rulesreader.py: Provides rule definitions from rule.d
    - fwmanage.py: Orchestrates firewall loading and installation
"""

from __future__ import annotations
from typing import TYPE_CHECKING, TypedDict, cast
import socket
import re
import ipaddress
import logging
from pathlib import Path

if TYPE_CHECKING:
    from .config import Config
    from .rulesreader import RulesReader

log = logging.getLogger('nftfw')


# Type alias for firewall rule records
class RecordDict(TypedDict, total=False):
    """Type definition for firewall rule record dictionaries.

    Required fields (set during initialisation):
        sourcefile: Path to the source file
        baseaction: Action name extracted from filename (after nn-)
        contents: Raw file contents as string
        direction: Either 'incoming' or 'outgoing'

    Added by validation:
        action: Validated action name (rule name or default action)
        ports: Port number as string (optional, only if action implies a port)
        ip: List of IPv4 addresses/networks as strings (optional)
        ip6: List of IPv6 addresses/networks as strings (optional)
    """
    sourcefile: Path
    baseaction: str
    contents: str
    direction: str
    action: str
    ports: str
    ip: list[str]
    ip6: list[str]


class FirewallReader:
    """Reads and validates firewall rule files from incoming.d or outgoing.d.

    This class scans a directory for numbered rule files (nn-action format), reads
    their contents, validates the action and any IP addresses/hostnames, and creates
    a list of structured records for processing by FirewallProcess.

    The validation process:
        1. Action validation: Checks if action is a known rule, port number, or service
        2. Contents validation: Validates IP addresses, networks, and resolves hostnames
        3. Protocol separation: Maintains separate lists for IPv4 and IPv6

    Attributes:
        cf: Config instance providing paths and configuration settings
        direction: Either 'incoming' or 'outgoing' to determine which directory to read
        rulesreader: RulesReader instance (loaded externally and stored in cf)
        records: List of validated rule records, ordered by filename number
        addfn: Class-level mapping of protocol to ipaddress address type
        netfn: Class-level mapping of protocol to ipaddress network type

    Note:
        The rulesreader attribute is populated externally by fwmanage.py before
        FirewallReader is instantiated. This allows sharing a single RulesReader
        instance across multiple FirewallReader instances.

    Example:
        >>> from config import Config
        >>> from rulesreader import RulesReader
        >>> cf = Config()
        >>> cf.rulesreader = RulesReader(cf)
        >>> reader = FirewallReader(cf, 'incoming')
        >>> # Process records
        >>> for rec in reader.records:
        ...     print(f"File: {rec['sourcefile'].name}")
        ...     print(f"Action: {rec['action']}")
        ...     if 'ip' in rec:
        ...         print(f"IPv4: {rec['ip']}")
        ...     if 'ip6' in rec:
        ...         print(f"IPv6: {rec['ip6']}")

    See Also:
        - RulesReader: Provides rule definitions for action validation
        - FirewallProcess: Processes records to generate nftables commands
    """

    # Function mapping for IP address checking
    addfn: dict[str, type[ipaddress.IPv4Address | ipaddress.IPv6Address]] = {
        'ip':  ipaddress.IPv4Address,
        'ip6': ipaddress.IPv6Address
    }
    netfn: dict[str, type[ipaddress.IPv4Network | ipaddress.IPv6Network]] = {
        'ip':  ipaddress.IPv4Network,
        'ip6': ipaddress.IPv6Network
    }

    def __init__(self, cf: Config, direction: str) -> None:
        """Initialize FirewallReader and load rule files from specified directory.

        Scans the incoming.d or outgoing.d directory for files matching the nn-action
        pattern, reads their contents, and validates all rules. Files are processed
        in numerical order (00-99).

        Args:
            cf: Config instance providing etcpath() and configuration settings
            direction: Either 'incoming' or 'outgoing' to select directory

        Note:
            The cf.rulesreader attribute must be set before instantiation.
            This is done by fwmanage.py to share a single RulesReader instance.

        Example:
            >>> from config import Config
            >>> from rulesreader import RulesReader
            >>> cf = Config()
            >>> cf.rulesreader = RulesReader(cf)
            >>> reader = FirewallReader(cf, 'incoming')
            >>> len(reader.records)  # Number of valid rules found
            5
        """
        self.cf: Config = cf
        self.direction: str = direction
        path: Path = cf.etcpath(direction)

        # enforce strict checking on the name, assisting
        # emacs users that might get ~ appended to the name
        strict: re.Pattern[str] = re.compile(r'[0-9][0-9]-[-_a-z0-9]*$', re.I)

        self.records: list[RecordDict] = [
            RecordDict(
                sourcefile=p,
                baseaction=p.stem[3:],
                contents=p.read_text(),
                direction=direction
            )
            for p in sorted(path.glob('[0-9][0-9]-*'))
            if strict.match(p.stem) is not None and p.is_file()
        ]

        # rulesreader is loaded externally in fwmanage
        # and stored in cf so it can be shared
        self.rulesreader: RulesReader = cf.rulesreader
        self.validate()

    def validate(self) -> None:
        """Validate all records in self.records.

        Iterates through all loaded records, validating the action and contents
        for each. Invalid records (e.g., unknown service names) are logged and
        removed from the list.

        The validation process:
            1. Validate action (rule name, port, or service)
            2. If file has contents, validate IP addresses and hostnames
            3. Keep only successfully validated records

        Note:
            This method modifies self.records in place, removing invalid entries.

        Example:
            >>> reader = FirewallReader(cf, 'incoming')
            >>> # Validation happens automatically during __init__
            >>> # Invalid rules are logged and removed
            >>> all('action' in rec for rec in reader.records)
            True
        """
        newrecords: list[RecordDict] = []
        for rec in self.records:
            # First validate action, then if contents validate them
            try:
                self.validateaction(rec)
                if rec['contents'] != '':
                    self.validatecontents(rec)
                newrecords.append(rec)
            except OSError as e:
                # getservbyname failing - so rule isn't valid
                log.error('%s: %s', rec['sourcefile'], str(e))
        self.records = newrecords

    def validateaction(self, f: RecordDict) -> None:
        """Validate and determine the action for a single rule record.

        Determines the action by checking in order:
            1. Is this a known rule from RulesReader? Use the rule name
            2. Is this a numeric port? Use default action and set ports
            3. Is this a service name in /etc/services? Look up port and use default action

        Args:
            f: Rule record dictionary to validate and modify

        Raises:
            OSError: If service name lookup fails (from socket.getservbyname)

        Note:
            Modifies the input dictionary in place, adding 'action' and optionally 'ports'.

        Example:
            >>> rec = {'baseaction': 'ssh', 'sourcefile': Path('10-ssh'), ...}
            >>> reader.validateaction(rec)
            >>> rec['action']
            'accept'
            >>> rec['ports']
            '22'

            >>> rec = {'baseaction': 'webserver', ...}  # webserver rule exists
            >>> reader.validateaction(rec)
            >>> rec['action']
            'webserver'
            >>> 'ports' in rec
            False
        """
        # action used when it's implied from a port in the name
        default_action: str = cast(str, self.cf.get_ini_value_from_section('Rules', self.direction))

        # Evaluate rule:
        # 1. is this a rule we know about? If so use it
        # 2. Is this a numeric value then it's a port number
        # 3. Is this the name of a service in /etc/services?
        #    lookup portname in /etc/services and get port

        if self.rulesreader.exists(f['baseaction']):
            f['action'] = f['baseaction']
        elif f['baseaction'].isnumeric():
            f['action'] = default_action
            f['ports'] = f['baseaction']
        else:
            # may trigger an OSError exception
            f['ports'] = str(socket.getservbyname(f['baseaction']))
            f['action'] = default_action

    def validatecontents(self, f: RecordDict) -> None:
        """Validate and process IP addresses and hostnames from file contents.

        Parses the file contents (one entry per line) and validates each entry as:
            1. IPv4 address or network (CIDR notation)
            2. IPv6 address or network (CIDR notation)
            3. Hostname (resolved via DNS to IPv4/IPv6 addresses)

        Duplicates are removed and results are sorted for consistent ordering.

        Args:
            f: Rule record dictionary to validate and modify

        Note:
            Modifies the input dictionary in place, adding 'ip' and/or 'ip6' lists.
            Invalid addresses are logged and skipped.

        Example:
            >>> rec = {
            ...     'contents': '192.168.1.1\\n10.0.0.0/8\\n2001:db8::1\\nexample.com',
            ...     'sourcefile': Path('10-test'),
            ...     ...
            ... }
            >>> reader.validatecontents(rec)
            >>> rec['ip']
            ['10.0.0.0/8', '192.168.1.1', '198.51.100.1']  # example.com resolved
            >>> rec['ip6']
            ['2001:db8::1', '2001:db8::2']  # example.com IPv6
        """
        # lists we are generating
        # use sets to remove duplicates
        ip: list[str] = []
        ip6: list[str] = []

        # first split the contents into a list
        srclist: list[str] = [v.strip() for v in f['contents'].split('\n') if v != '']

        # check the address
        # 1. check for ip4 using regex (can be a network with /)
        #    need ip format to allow for hostnames
        #    but re doesn't need to check for /
        # 2. if it has a ':' then it's ipv6
        # 3. otherwise it might be a hostname and
        #    we need to convert to a set of addresses
        # 4. ensure lists are sorted so that they remain
        #    in constant order
        ip4fmt: re.Pattern[str] = re.compile(r'(?:[0-9]{1,3}\.){3}[0-9]{1,3}')
        for possible in srclist:
            if ip4fmt.match(possible) is not None:
                norm: str | None = self.ipcheck('ip', possible, f['sourcefile'])
                if norm:
                    ip.append(norm)
            elif ':' in possible:
                norm = self.ipcheck('ip6', possible, f['sourcefile'])
                if norm:
                    ip6.append(norm)
            else:
                self.hostnamecheck(possible, ip, ip6, f['sourcefile'])

        # set up the output
        if any(ip):
            f['ip'] = sorted(list(set(ip)))
        if any(ip6):
            f['ip6'] = sorted(list(set(ip6)))

    def ipcheck(self, proto: str, p: str, srcfile: Path) -> str | None:
        """Validate an IP address or network using ipaddress module.

        Args:
            proto: Protocol type, either 'ip' (IPv4) or 'ip6' (IPv6)
            p: IP address or network string to validate
            srcfile: Source file path (used in error messages)

        Returns:
            Normalized address/network string if valid, None if invalid

        Note:
            Uses strict=False for networks to allow host bits to be set.
            Logs errors for invalid addresses.

        Example:
            >>> reader.ipcheck('ip', '192.168.1.1', Path('10-test'))
            '192.168.1.1'
            >>> reader.ipcheck('ip', '10.0.0.0/8', Path('10-test'))
            '10.0.0.0/8'
            >>> reader.ipcheck('ip', '999.999.999.999', Path('10-test'))
            None  # Logged as error
        """
        addfn: type[ipaddress.IPv4Address | ipaddress.IPv6Address] = self.addfn[proto]
        netfn: type[ipaddress.IPv4Network | ipaddress.IPv6Network] = self.netfn[proto]

        try:
            if '/' in p:
                i: ipaddress.IPv4Network | ipaddress.IPv6Network = netfn(p, strict=False)
            else:
                i = addfn(p)  # type: ignore[assignment]
            return str(i)
        except ipaddress.AddressValueError as e:
            log.error('%s: %s: %s', srcfile, p, str(e))
            return None

    @staticmethod
    def hostnamecheck(poss: str, ip: list[str], ip6: list[str], filename: Path) -> None:
        """Resolve hostname to IP addresses via DNS and update IP lists.

        Uses socket.getaddrinfo() to perform DNS lookup and appends any found
        IPv4 and IPv6 addresses to the provided lists.

        Args:
            poss: Possible hostname to resolve
            ip: IPv4 address list to append results to (modified in place)
            ip6: IPv6 address list to append results to (modified in place)
            filename: Source file path (used in error messages)

        Note:
            - Modifies ip and ip6 lists in place
            - Logs error if hostname lookup fails
            - Will not return IPv6 if host is not configured for IPv6

        Example:
            >>> ip = []
            >>> ip6 = []
            >>> FirewallReader.hostnamecheck('example.com', ip, ip6, Path('10-test'))
            >>> ip
            ['93.184.216.34']
            >>> ip6
            ['2606:2800:220:1:248:1893:25c8:1946']
        """
        # NB will not return ipv6 if host is not configured for it
        try:
            res = socket.getaddrinfo(poss, None)
        except socket.gaierror:
            log.error("%s: %s hostname lookup failed", filename, poss)
            return

        # returns an array of addresses in a 5 tuple
        # (family, type, proto, canonname, sockaddr)
        # family is a constant
        # sockaddr is a tuple with element 0 being the address
        for family, iptype, proto, c, addr in res:  # pylint: disable=unused-variable
            sockaddr: tuple = addr
            if family == socket.AF_INET:
                ip.append(sockaddr[0])
            elif family == socket.AF_INET6:
                ip6.append(sockaddr[0])
