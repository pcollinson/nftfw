#!/usr/bin/env python3
"""nftfw ListReader and SetName classes - IP list file processing.

This module provides classes for reading and processing IP address list files
from the whitelist.d and blacklist.d directories. It handles file parsing,
port validation, IP address validation, and generation of nftables set names.

Key Features:
- Reads IP address files from whitelist.d and blacklist.d directories
- Validates IP addresses (both IPv4 and IPv6, addresses and networks)
- Validates and normalises port lists from file contents
- Compiles IP lists into protocol-separated records for nftables
- Generates unique nftables set names with collision handling
- Supports disabled file to skip directory processing

File Naming Convention:
----------------------
Files in whitelist.d and blacklist.d follow these patterns:
- IP address: "192.168.1.100" or "2001:db8::1"
- CIDR network: "192.168.1.0|24" (| replaces / in filenames)
- Auto-generated: "192.168.1.100.auto" (created by system, auto-expires)

File Contents:
-------------
Each file contains port numbers (one per line) or the keyword "all":
- Empty file or "all" → applies to all ports
- Port list: numeric values, one per line (e.g., "22", "80", "443")

Data Structures:
---------------
srcdict: Raw data from files
    {
        "192.168.1.100": "22,80,443",
        "10.0.0.0/8": "all",
        "2001:db8::1": "22"
    }

records: Compiled data organised by port sets
    {
        "22,80,443": {
            "ip": ["192.168.1.100"],
            "ip6": [],
            "name": "b_22_80_443"
        },
        "all": {
            "ip": ["10.0.0.0/8"],
            "ip6": ["2001:db8::1"],
            "name": "b_all"
        }
    }

Usage Example:
-------------
    from .config import Config
    from .listreader import ListReader

    cf = Config()

    # Read blacklist for full compilation
    blacklist = ListReader(cf, 'blacklist', need_compiled_ix=True)

    # Access raw IP to ports mapping
    for ip, ports in blacklist.srcdict.items():
        print(f"{ip}: {ports}")

    # Access compiled records for nftables
    for ports, record in blacklist.records.items():
        print(f"Set {record['name']} for ports {ports}:")
        print(f"  IPv4: {record.get('ip', [])}")
        print(f"  IPv6: {record.get('ip6', [])}")

    # Read whitelist without compilation (just need IP list)
    whitelist = ListReader(cf, 'whitelist', need_compiled_ix=False)
    ip_list = list(whitelist.srcdict.keys())

SetName Usage Example:
---------------------
    from .listreader import SetName

    # Create name generator for blacklist
    sn = SetName('blacklist')

    # Generate names for different port sets
    name1 = sn.name('22,80,443')     # Returns: "b_22_80_443"
    name2 = sn.name('all')           # Returns: "b_all"
    name3 = sn.name('22,80')         # Returns: "b_22_80"

    # Handles name collisions automatically
    name4 = sn.name('22,80,443')     # Returns: "b1_22_80_443" (collision!)

See Also:
--------
- blacklist.py: Uses ListReader to get blacklisted IPs for file creation
- whitelist.py: Uses ListReader to get whitelisted IPs for file creation
- whitelistcheck.py: Uses ListReader to load whitelist for validation
- firewallprocess.py: Uses ListReader to compile lists for nftables
"""
from __future__ import annotations

import ipaddress
import logging
import re
from ipaddress import (
    IPv4Address,
    IPv4Network,
    IPv6Address,
    IPv6Network,
)
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .config import Config

log = logging.getLogger('nftfw')

# Type alias for IP address objects (address or network)
IpAddressType = IPv4Address | IPv4Network | IPv6Address | IPv6Network


class ListReader:
    """Read and process IP address list files from whitelist.d or blacklist.d.

    This class loads IP address files from the specified directory (whitelist.d
    or blacklist.d), validates IP addresses and port specifications, and compiles
    the data into structures suitable for nftables set generation.

    The class provides two levels of data access:
    1. srcdict: Raw IP-to-ports mapping directly from files
    2. records: Compiled data organised by port sets for nftables generation

    Files in the directory are named by IP address (with | replacing / for CIDR),
    optionally followed by .auto for automatically generated entries. Each file
    contains port numbers (one per line) or the keyword "all".

    Attributes:
        cf: Configuration instance providing paths and settings
        listname: Name of the list being processed ('whitelist' or 'blacklist')
        path: Path to the list directory (whitelist.d or blacklist.d)
        srcdict: Dictionary mapping IP addresses (str) to port lists (str).
            Keys are IP addresses from filenames, values are comma-separated
            port lists or 'all'. This is the raw data from files.
        records: Dictionary mapping port lists (str) to protocol-separated
            IP lists with nftables set names. Only created if need_compiled_ix=True.
            Structure: {ports: {'ip': [ips], 'ip6': [ips], 'name': setname}}

    Example:
        >>> from .config import Config
        >>> cf = Config()
        >>> # Full compilation for blacklist
        >>> bl = ListReader(cf, 'blacklist', need_compiled_ix=True)
        >>> print(bl.srcdict)
        {'192.168.1.100': '22,80', '10.0.0.1': 'all'}
        >>> print(bl.records)
        {'22,80': {'ip': ['192.168.1.100'], 'name': 'b_22_80'},
         'all': {'ip': ['10.0.0.1'], 'name': 'b_all'}}
        >>>
        >>> # Just need IP list (no compilation)
        >>> wl = ListReader(cf, 'whitelist', need_compiled_ix=False)
        >>> ip_list = list(wl.srcdict.keys())

    Note:
        If a file named "disabled" exists in the directory, all processing
        is skipped and empty dictionaries are returned. This allows temporary
        disabling of whitelist or blacklist functionality.

    See Also:
        SetName: Generates nftables set names for compiled records
        blacklist.py: Uses ListReader to manage blacklist files
        whitelist.py: Uses ListReader to manage whitelist files
    """

    def __init__(
        self, cf: Config, listname: str, need_compiled_ix: bool = True
    ) -> None:
        """Initialize ListReader and load data from the specified directory.

        Reads all IP address files from the whitelist.d or blacklist.d
        directory, validates their contents, and optionally compiles them
        into protocol-separated records for nftables set generation.

        Args:
            cf: Configuration instance providing directory paths
            listname: Name of list to read, either 'whitelist' or 'blacklist'
            need_compiled_ix: If True, create compiled records structure for
                nftables. If False, only create srcdict (raw IP-to-ports mapping).
                Set to False when only the IP list is needed (e.g., whitelist
                checking) to save processing time. Defaults to True.

        Example:
            >>> from .config import Config
            >>> cf = Config()
            >>>
            >>> # Full compilation (for nftables generation)
            >>> bl = ListReader(cf, 'blacklist', need_compiled_ix=True)
            >>> # Use both srcdict and records
            >>>
            >>> # Just IP list (for whitelist checking)
            >>> wl = ListReader(cf, 'whitelist', need_compiled_ix=False)
            >>> # Only srcdict available, records not created

        Note:
            The initialisation process:
            1. Determines directory path (whitelist.d or blacklist.d)
            2. Calls loadfile() to read and validate files
            3. If need_compiled_ix=True, calls compileix() to organise by ports
            4. Invalid IP addresses are logged and skipped
            5. Port lists are validated and normalised
        """
        self.cf: Config = cf
        self.listname: str = listname
        self.path: Path = cf.etcpath(listname)
        self.srcdict: dict[str, str] = self.loadfile()
        if need_compiled_ix:
            self.records: dict[str, dict[str, Any]] = self.compileix(self.srcdict)

    def loadfile(self) -> dict[str, str]:
        """Read and validate files from the list directory.

        Scans the directory for files matching IP address patterns, validates
        the IP addresses, and reads port specifications from file contents.
        Files are named by IP address with optional CIDR notation (using |
        instead of /) and optional .auto suffix.

        File name patterns:
        - "192.168.1.100" → single IPv4 address
        - "192.168.1.0|24" → IPv4 network (| replaces /)
        - "2001:db8::1" → single IPv6 address
        - "2001:db8::|112" → IPv6 network
        - Any of the above followed by ".auto" → auto-generated entry

        Returns:
            Dictionary mapping IP addresses (str) to comma-separated port
            lists (str) or 'all'. Returns empty dict if disabled file exists.

        Example:
            >>> # Assuming whitelist.d contains:
            >>> # 192.168.1.100 (containing "22\n80")
            >>> # 10.0.0.0|8.auto (containing "all")
            >>> srcdict = lr.loadfile()
            >>> print(srcdict)
            {'192.168.1.100': '22,80', '10.0.0.0/8': 'all'}

        Note:
            - Returns empty dict {} if "disabled" file exists in directory
            - Invalid IP addresses in filenames are logged and skipped
            - Port validation is performed by portcheck() method
            - | in filename is converted to / for standard CIDR notation
            - .auto suffix is stripped from filename
            - Only files (not directories) are processed
        """
        # symbiosis allows a file called disabled to exist to
        # stop list compilation
        disabled = self.path / 'disabled'
        if disabled.exists():
            return {}

        # re matches
        # sequence of 0-9a-f . or : as far as it can
        #     captured in match[1]
        # followed optionally by | and one, two or three digits
        #     captured in match[2]
        # followed optionally by .auto
        strict = re.compile(r'([0-9a-f.:]*?)(\|[0-9]{1,3})?(?:\.auto)?$', re.I)
        srcdict: dict[str, str] = {}
        for p in sorted(self.path.glob('[0-9a-z]*')):
            ma = strict.match(p.name)
            if ma is not None and p.is_file():
                key = ma.group(1)
                if ma.group(2) is not None:
                    key = key + '/' + ma.group(2)[1:]
                ports = p.read_text()
                srcdict[key] = self.portcheck(ports)
        return srcdict

    def compileix(self, srcdict: dict[str, str]) -> dict[str, dict[str, Any]]:
        """Compile raw IP-to-ports mapping into protocol-separated records.

        Takes the raw srcdict and reorganizes it by port sets, separating
        IPv4 and IPv6 addresses, and generating nftables set names. This
        structure is optimised for nftables set generation.

        The compilation process:
        1. Validate each IP address string
        2. Group IPs by their port specifications
        3. Separate IPv4 and IPv6 within each port group
        4. Generate unique nftables set names for each port group
        5. Remove duplicates within each protocol

        Args:
            srcdict: Dictionary mapping IP addresses to port lists,
                as returned by loadfile()

        Returns:
            Dictionary mapping port lists to protocol-separated IP lists
            with nftables set names. Structure:
            {
                "port_list": {
                    "ip": ["ipv4_addr1", "ipv4_addr2", ...],
                    "ip6": ["ipv6_addr1", "ipv6_addr2", ...],
                    "name": "nftables_set_name"
                },
                ...
            }

        Example:
            >>> srcdict = {
            ...     '192.168.1.100': '22,80',
            ...     '10.0.0.1': '22,80',
            ...     '2001:db8::1': '443',
            ...     '10.0.0.2': 'all'
            ... }
            >>> records = lr.compileix(srcdict)
            >>> print(records)
            {
                '22,80': {
                    'ip': ['192.168.1.100', '10.0.0.1'],
                    'ip6': [],
                    'name': 'b_22_80'
                },
                '443': {
                    'ip': [],
                    'ip6': ['2001:db8::1'],
                    'name': 'b_443'
                },
                'all': {
                    'ip': ['10.0.0.2'],
                    'ip6': [],
                    'name': 'b_all'
                }
            }

        Note:
            - Invalid IP addresses are logged and skipped
            - Duplicate IPs within a protocol are removed
            - IPv4 and IPv6 are always separated into different lists
            - Set names are generated using the SetName class
            - Protocol keys ('ip' or 'ip6') only exist if addresses are present
        """
        master: dict[str, dict[str, Any]] = {}
        for ip, ports in srcdict.items():
            ipv = self.validateip(ip)
            if ipv is not None:
                if ports not in master:
                    master[ports] = {}
                if ipv.version == 4:
                    proto = 'ip'
                else:
                    proto = 'ip6'
                if proto not in master[ports]:
                    master[ports][proto] = []
                if str(ipv) not in master[ports][proto]:
                    master[ports][proto].append(str(ipv))
        # now deal with names for the entries
        # initialise the name generator
        setname = SetName(self.listname)
        # pylint: disable=consider-using-dict-items
        # duely considered
        for ports in master:
            name = setname.name(ports)
            master[ports]['name'] = name
        return master

    @staticmethod
    def portcheck(ptstr: str) -> str:
        """Validate and normalise port list from file contents.

        Takes port specification from file contents and validates it,
        returning a normalised comma-separated list of ports or 'all'.

        Processing rules:
        - Empty string → 'all'
        - Contains 'all' (case-insensitive) → 'all'
        - Numeric values → sorted, deduplicated, comma-separated list
        - Blank lines and non-numeric lines are ignored
        - Commas are treated as newlines (for convenience)

        Args:
            ptstr: Raw port specification from file contents, may contain
                newlines, whitespace, and multiple formats

        Returns:
            Normalized port specification: either 'all' or comma-separated
            sorted numeric list (e.g., '22,80,443')

        Example:
            >>> ListReader.portcheck('')
            'all'
            >>> ListReader.portcheck('all')
            'all'
            >>> ListReader.portcheck('80\\n22\\n443\\n22')
            '22,80,443'
            >>> ListReader.portcheck('80, 443, 22')  # commas accepted
            '22,80,443'
            >>> ListReader.portcheck('22\\n\\n80\\ninvalid\\n443')
            '22,80,443'

        Note:
            - Port numbers are sorted numerically for consistency
            - Duplicates are automatically removed
            - Non-numeric lines are silently ignored
            - Leading/trailing whitespace is stripped from each line
            - The 'all' keyword check is case-insensitive
        """
        # look for 'all' in contents
        if 'all' in ptstr.casefold():
            return 'all'
        # make an array of ints so we can sort them
        # shouldn't have commas, but people may type them
        pt = ptstr.replace(',', '\n')
        # split at newlines also lose any whitespace
        li = [n.strip() for n in pt.split("\n") if n.strip().isnumeric()]
        if any(li):
            li = list(set(li))
            li = sorted(li, key=int)
            return ','.join(li)
        return 'all'

    def validateip(self, ip: str) -> IpAddressType | None:
        """Validate IP address string and return ipaddress object.

        Parses an IP address or network string and returns the appropriate
        ipaddress object (IPv4Address, IPv4Network, IPv6Address, or IPv6Network).
        Invalid addresses are logged and None is returned.

        Args:
            ip: IP address string, may be:
                - Single address: "192.168.1.100" or "2001:db8::1"
                - CIDR network: "192.168.1.0/24" or "2001:db8::/112"

        Returns:
            An ipaddress object (IPv4Address, IPv4Network, IPv6Address, or
            IPv6Network) if valid, None if invalid

        Example:
            >>> lr.validateip('192.168.1.100')
            IPv4Address('192.168.1.100')
            >>> lr.validateip('192.168.1.0/24')
            IPv4Network('192.168.1.0/24')
            >>> lr.validateip('2001:db8::1')
            IPv6Address('2001:db8::1')
            >>> lr.validateip('invalid')
            None  # Error logged

        Note:
            - Uses ipaddress.ip_address() for single addresses
            - Uses ipaddress.ip_network(strict=False) for networks
            - CIDR networks have host bits set to 0 (strict=False)
            - Invalid addresses are logged with path and error details
            - The returned object's .version attribute (4 or 6) indicates protocol
        """
        try:
            i: IpAddressType
            if '/' in ip:
                i = ipaddress.ip_network(ip, strict=False)  # type: ignore[assignment]
            else:
                i = ipaddress.ip_address(ip)  # type: ignore[assignment]
            return i
        except ValueError as e:
            log.error('%s: %s: %s', self.path, ip, str(e))
            return None


class SetName:
    """Generate unique nftables set names with collision handling.

    This class generates consistent, readable names for nftables sets based
    on port specifications. Names follow the pattern: prefix_ports, where
    prefix is derived from the list name (b for blacklist, w for whitelist)
    and ports are underscore-separated port numbers.

    Names are limited to 16 characters to comply with nftables restrictions.
    When collisions occur (same name generated twice), a sequence number is
    added after the prefix to ensure uniqueness.

    Name Format:
    -----------
    - Normal: "b_22_80_443" (blacklist, ports 22,80,443)
    - Collision: "b1_22_80_443" (second instance with same ports)
    - Truncated: "b_22_80_443_53" → "b_22_80_443_5" (16 char limit)

    Attributes:
        prefix: Single character prefix from list name ('b' or 'w')
        checkdict: Dictionary tracking generated names to detect collisions,
            maps name to sequence number ('' for first occurrence)

    Example:
        >>> sn = SetName('blacklist')
        >>> sn.name('22,80,443')
        'b_22_80_443'
        >>> sn.name('all')
        'b_all'
        >>> sn.name('22,80,443')  # Collision!
        'b1_22_80_443'
        >>> sn.name('22,80,443')  # Another collision!
        'b2_22_80_443'
        >>>
        >>> sn2 = SetName('whitelist')
        >>> sn2.name('22')
        'w_22'

    Note:
        Each SetName instance maintains its own collision tracking, so
        different instances can generate the same names independently.
        This is typically what you want for separate list types.

    See Also:
        ListReader.compileix: Uses SetName to generate names for records
    """

    def __init__(self, listname: str) -> None:
        """Initialize SetName with list type prefix.

        Args:
            listname: Name of list type, e.g., 'blacklist' or 'whitelist'.
                The first character is used as the set name prefix.

        Example:
            >>> sn = SetName('blacklist')
            >>> sn.prefix
            'b'
            >>> sn = SetName('whitelist')
            >>> sn.prefix
            'w'

        Note:
            Only the first character of listname is used, so any string
            starting with 'b' or 'w' will work appropriately.
        """
        self.prefix: str = listname[:1]
        #
        # Dict to remember lookups and store prefix values
        self.checkdict: dict[str, str] = {}

    def name(self, ports: str) -> str:
        """Generate nftables set name from port specification.

        Converts a comma-separated port list into an underscore-separated
        nftables set name, with automatic collision handling and length
        limiting to 16 characters.

        Args:
            ports: Comma-separated port list (e.g., '22,80,443') or 'all'

        Returns:
            Generated set name (max 16 characters) with collision handling

        Example:
            >>> sn = SetName('blacklist')
            >>> sn.name('22,80,443')
            'b_22_80_443'
            >>> sn.name('all')
            'b_all'
            >>> sn.name('1,2,3,4,5,6,7,8,9')
            'b_1_2_3_4_5_6_'  # Truncated to 16 chars
            >>> sn.name('22,80,443')  # Duplicate call
            'b1_22_80_443'    # Sequence number added

        Note:
            - Commas in ports are replaced with underscores
            - Prefix + underscore + ports, e.g., "b_22_80"
            - Names truncated to fit 16 character limit
            - Collisions handled by adding sequence number after prefix
            - First occurrence has no number, subsequent get 1, 2, 3, etc.
        """
        portsname = "_".join(ports.split(","))
        return self.mkname('', portsname)

    def mkname(self, seq: str, body: str) -> str:
        """Generate set name with collision handling (recursive).

        This is the internal recursive method that handles name generation,
        truncation, and collision detection. It builds the name from prefix,
        sequence number (if any), and body, then checks for collisions.

        The recursion handles collisions: if a generated name already exists,
        the sequence number is incremented and the method calls itself with
        the new sequence number.

        Args:
            seq: Sequence number as string, '' for first attempt (no collision)
            body: Port-based body of the name (already underscore-separated)

        Returns:
            Unique set name (max 16 characters)

        Example (internal method, typically not called directly):
            >>> sn = SetName('blacklist')
            >>> sn.mkname('', '22_80_443')
            'b_22_80_443'
            >>> # After collision detected:
            >>> sn.mkname('1', '22_80_443')
            'b1_22_80_443'

        Note:
            - Body is truncated if total length > 16 characters
            - Format: prefix + seq + "_" + body (e.g., "b1_22_80_443")
            - Sequence starts at '' (no number), then 0, 1, 2, ...
            - First collision gets sequence 0, subsequent get 1, 2, 3, ...
            - Recursion depth limited by number of collisions (typically very low)
        """
        mainlen = len(seq) + len(body)
        if mainlen > 14:
            body = body[: 14 - mainlen]
        trial = self.namefmt(seq, body)

        # pylint: disable=consider-iterating-dictionary
        # I am looking up not iterating
        if trial in self.checkdict.keys():
            # we've had this before
            seqno_str = self.checkdict[trial]
            seqno_int: int
            if seqno_str == '':
                seqno_int = 0
            else:
                seqno_int = int(seqno_str)
            seqno_int += 1
            return self.mkname(str(seqno_int), body)

        self.checkdict[trial] = seq
        return trial

    def namefmt(self, seq: str, portsname: str) -> str:
        """Format the complete set name from components.

        Simple formatting function that combines prefix, sequence number,
        and port-based name into the final set name.

        Args:
            seq: Sequence number string ('' for no collision, '0', '1', etc.)
            portsname: Port-based name body (underscore-separated)

        Returns:
            Formatted set name: prefix + seq + "_" + portsname

        Example:
            >>> sn = SetName('blacklist')
            >>> sn.namefmt('', '22_80_443')
            'b_22_80_443'
            >>> sn.namefmt('1', '22_80_443')
            'b1_22_80_443'
            >>> sn.namefmt('10', 'all')
            'b10_all'

        Note:
            This is a simple formatting method with no validation or
            collision checking. Collision handling is done by mkname().
        """
        return f'{self.prefix}{seq}_{portsname}'
