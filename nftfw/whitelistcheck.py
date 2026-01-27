"""nftfw WhiteListCheck class - IP validation for blacklist integration.

This module provides whitelist checking functionality to validate IP addresses
against the system whitelist before blacklisting them. It reads whitelist
entries from the whitelist.d directory and provides efficient lookup methods
for both individual addresses and networks.

Key Features:
- Loads whitelist entries from whitelist.d via ListReader
- Supports both IPv4 and IPv6 addresses and networks
- Fast lookup with optimisation for common cases (exact matches)
- Network matching with subnet checking
- Shared NormaliseAddress instance for integration with other modules

Architecture:
-----------
The WhiteListCheck class is typically instantiated by blacklist.py to filter
out whitelisted IPs before adding them to the blacklist database. It maintains
two separate lists (one for IPv4, one for IPv6) and tracks whether networks
are present to optimise lookups.

Workflow:
1. Initialization loads all whitelist entries from whitelist.d
2. Entries are parsed and stored as ipaddress objects (Address or Network)
3. is_white() method checks if an IP should be excluded from blacklisting
4. Lookup proceeds from fast (exact match) to slower (subnet check)

Usage Example:
-------------
    from .config import Config
    from .whitelistcheck import WhiteListCheck

    cf = Config()
    wlc = WhiteListCheck(cf)

    # Check if an IP is whitelisted
    from ipaddress import IPv4Address
    test_ip = IPv4Address('192.168.1.100')
    if wlc.is_white('ip', test_ip):
        print("IP is whitelisted, skip blacklisting")

    # Check IPv6
    from ipaddress import IPv6Address
    test_ip6 = IPv6Address('2001:db8::1')
    if wlc.is_white('ip6', test_ip6):
        print("IPv6 is whitelisted")

    # The normalise_addr attribute can be reused by calling code
    # to avoid creating duplicate NormaliseAddress instances
    validated = wlc.normalise_addr.normal_ipaddr('ip', '10.0.0.1')

Performance Optimization:
------------------------
- Exact match lookup is O(n) but typically fast for small lists
- Network matching only performed if networks exist
- havenets flag avoids unnecessary iteration for protocol without networks
- Most common case (exact match or not in list) exits early

See Also:
--------
- blacklist.py: Main consumer of this class
- normaliseaddress.py: IP address validation and normalisation
- listreader.py: Reads whitelist files from whitelist.d
"""
from __future__ import annotations

import logging
from ipaddress import (
    IPv4Address,
    IPv4Network,
    IPv6Address,
    IPv6Network,
)
from typing import TYPE_CHECKING

from .listreader import ListReader
from .normaliseaddress import NormaliseAddress

if TYPE_CHECKING:
    from .config import Config

log = logging.getLogger('nftfw')

# Type alias for IP address objects (address or network)
IpAddressType = IPv4Address | IPv4Network | IPv6Address | IPv6Network


class WhiteListCheck:
    """Check for IPs in whitelist to prevent blacklisting whitelisted addresses.

    This class loads whitelist entries from the whitelist.d directory and
    provides efficient lookup methods to determine if an IP address should
    be excluded from blacklisting. It supports both exact address matching
    and network subnet matching.

    The class maintains separate lists for IPv4 and IPv6, with optimisation
    flags to speed up lookups when no networks are present for a protocol.

    Attributes:
        cf: Configuration instance
        whitedict: Dictionary mapping protocol ('ip' or 'ip6') to lists of
            ipaddress objects (IPv4Address, IPv4Network, IPv6Address, IPv6Network)
        havenets: Dictionary tracking whether networks exist for each protocol,
            used to skip expensive subnet checks when unnecessary
        normalise_addr: Shared NormaliseAddress instance, also used by caller
            to avoid creating duplicate instances. Initially configured with
            error_name='Whitelist', then changed to 'Blacklist' for later use.

    Example:
        >>> from .config import Config
        >>> from ipaddress import IPv4Address, IPv4Network
        >>> cf = Config()
        >>> wlc = WhiteListCheck(cf)
        >>>
        >>> # Check exact match
        >>> ip = IPv4Address('192.168.1.100')
        >>> wlc.is_white('ip', ip)
        False
        >>>
        >>> # Check network match (if 192.168.1.0/24 is whitelisted)
        >>> net = IPv4Network('192.168.1.0/24')
        >>> if net in wlc.whitedict['ip']:
        ...     wlc.is_white('ip', ip)  # Returns True if subnet match

    Note:
        The normalise_addr attribute is shared with the calling code
        (typically blacklist.py) to avoid creating multiple instances.
        Its error_name is initially set to 'Whitelist' for loading the
        whitelist, then changed to 'Blacklist' for subsequent use.

    See Also:
        blacklist.py: Uses WhiteListCheck to filter IPs before blacklisting
        normaliseaddress.py: Provides IP validation and normalisation
        listreader.py: Reads whitelist files from whitelist.d directory
    """

    # pylint: disable=too-few-public-methods

    def __init__(self, cf: Config) -> None:
        """Initialize WhiteListCheck and load whitelist entries.

        Reads all whitelist files from whitelist.d directory using ListReader,
        normalises each entry into an ipaddress object, and stores them in
        protocol-specific lists for efficient lookup.

        The initialisation process:
        1. Uses ListReader to get all whitelist entries
        2. Creates NormaliseAddress instance for IP validation
        3. Iterates through entries, normalising each to ipaddress object
        4. Stores in whitedict['ip'] or whitedict['ip6'] based on protocol
        5. Tracks whether networks exist for each protocol (havenets)
        6. Changes normalise_addr.error_name to 'Blacklist' for later use

        Args:
            cf: Configuration instance providing paths and settings

        Example:
            >>> from .config import Config
            >>> cf = Config()
            >>> wlc = WhiteListCheck(cf)
            >>> # Now wlc.whitedict contains all whitelist entries
            >>> print(f"IPv4 entries: {len(wlc.whitedict['ip'])}")
            >>> print(f"IPv6 entries: {len(wlc.whitedict['ip6'])}")

        Note:
            Invalid IP addresses in whitelist files are logged and skipped.
            Duplicate entries are automatically filtered out (not added twice).
            The normalise_addr instance is shared with calling code for efficiency.
        """
        self.cf: Config = cf
        wf = ListReader(cf, 'whitelist', need_compiled_ix=False)
        whitelist = wf.srcdict.keys()

        self.whitedict: dict[str, list[IpAddressType]] = {'ip': [], 'ip6': []}
        # speed up lookups
        self.havenets: dict[str, bool] = {'ip': False, 'ip6': False}

        # used as a hook from blacklist.py
        # to avoid starting a new instance
        self.normalise_addr: NormaliseAddress = NormaliseAddress(
            cf, error_name='Whitelist'
        )

        for ipstr in whitelist:
            proto = 'ip'
            if ':' in ipstr:
                proto = 'ip6'
            ipa = self.normalise_addr.normal_ipaddr(proto, ipstr)
            if ipa is not None and ipa not in self.whitedict[proto]:
                self.whitedict[proto].append(ipa)
                if self.normalise_addr.is_network(proto, ipa):
                    self.havenets[proto] = True

        # set error prefix for later use
        self.normalise_addr.error_name = 'Blacklist'

    def is_white(self, proto: str, ipaddr: IpAddressType) -> bool:
        """Check if an IP address is in the whitelist.

        Performs efficient lookup to determine if an IP address should be
        excluded from blacklisting. The lookup proceeds in stages:

        1. Quick exit if no whitelist entries for this protocol
        2. Fast exact match check (most common case)
        3. Exit if no networks exist for this protocol
        4. Slow subnet check for network matching

        For network matching, two cases are handled:
        - If ipaddr is an address and whitelist contains a network,
          check if ipaddr is within that network
        - If ipaddr is a network and whitelist contains a network,
          check if ipaddr is a subnet of the whitelisted network

        Args:
            proto: Protocol identifier, either 'ip' (IPv4) or 'ip6' (IPv6)
            ipaddr: IP address object to check (IPv4Address, IPv4Network,
                IPv6Address, or IPv6Network)

        Returns:
            True if the IP address is whitelisted and should be excluded
            from blacklisting, False otherwise

        Example:
            >>> from ipaddress import IPv4Address, IPv4Network
            >>> # Assume whitelist contains 192.168.0.0/16
            >>> wlc = WhiteListCheck(cf)
            >>>
            >>> # Exact match
            >>> ip1 = IPv4Address('192.168.1.100')
            >>> wlc.is_white('ip', ip1)
            True  # if in whitelist
            >>>
            >>> # Network match
            >>> ip2 = IPv4Address('192.168.50.1')
            >>> wlc.is_white('ip', ip2)
            True  # matched by 192.168.0.0/16 network
            >>>
            >>> # Not whitelisted
            >>> ip3 = IPv4Address('10.0.0.1')
            >>> wlc.is_white('ip', ip3)
            False

        Note:
            Performance is optimised for common cases:
            - Empty whitelist returns immediately
            - Exact match (most common) is checked first
            - Network matching only performed if networks exist

            The protocol parameter must be 'ip' or 'ip6' to match
            the internal dictionary keys.
        """
        if not any(self.whitedict[proto]):
            return False

        # most common case
        if ipaddr in self.whitedict[proto]:
            return True

        # exit if no networks for this protocol
        if not self.havenets[proto]:
            return False

        # check for subnets
        ipaddr_is_network = self.normalise_addr.is_network(proto, ipaddr)

        # if the stored value is a net
        # return True if ipaddr a subnet of it
        # or if ipaddr is part of the net
        for k in self.whitedict[proto]:
            if self.normalise_addr.is_network(proto, k):
                if ipaddr_is_network:
                    if ipaddr.subnet_of(k):  # type: ignore[union-attr,arg-type]
                        return True
                elif ipaddr in k:  # type: ignore[operator]
                    return True
        return False
