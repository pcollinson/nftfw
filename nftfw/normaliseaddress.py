"""IP address normalisation and validation for nftfw.

This module provides the NormaliseAddress class for centralising all IP address
validation and normalisation logic. It handles both IPv4 and IPv6 addresses,
filters local/non-global addresses, integrates with whitelist checking, and
supports test mode for development.

Key Features:
    - IPv4 and IPv6 address validation and normalisation
    - Automatic IPv6 network creation (default /112 mask)
    - Local/non-global address filtering (production mode)
    - Whitelist integration via callback pattern
    - Test mode support (allows local addresses)
    - Comprehensive error logging with context

Usage Example:
    from .config import Config
    from .normaliseaddress import NormaliseAddress

    cf = Config()
    normalise = NormaliseAddress(cf, error_name='Blacklist')

    # Normalize an IPv4 address
    addr = normalise.normal('192.0.2.100')  # Returns '192.0.2.100'

    # Local address is ignored in production mode
    local = normalise.normal('192.168.1.1')  # Returns None

    # With whitelist checking
    def is_white_callback(proto, ipaddr):
        return proto == 'ip' and ipaddr in whitelist

    addr = normalise.normal('203.0.113.50', is_white=is_white_callback)

    # IPv6 address is converted to /112 network
    ipv6_net = normalise.normal('2001:db8::1')  # Returns '2001:db8::/112'

Architecture:
    - normal(): String input → string output (or None)
    - normal_ipaddr(): String input → ipaddress object output (or None)
    - _normal_ipaddr_prod(): Production mode (filters non-global)
    - _normal_ipaddr_test(): Test mode (allows local addresses)
    - make_ipaddr(): Creates ipaddress.IPv4Address/IPv6Network objects
    - is_network(): Type checking for network objects

Configuration:
    - default_ipv6_mask: Network mask for IPv6 (default /112)
    - TESTING: Flag to enable test mode (allows local addresses)

See Also:
    - whitelistcheck.py: Uses NormaliseAddress for whitelist validation
    - listreader.py: Uses NormaliseAddress for list file processing
    - blacklist.py: Uses NormaliseAddress for blacklist IP validation
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Callable
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
import ipaddress
import logging

if TYPE_CHECKING:
    from .config import Config

# Type alias for IP address types (matches whitelistcheck.py and listreader.py)
IpAddressType = IPv4Address | IPv4Network | IPv6Address | IPv6Network

log = logging.getLogger('nftfw')

class NormaliseAddress:
    """Centralised IP address normalisation and validation.

    This class provides a unified interface for validating and normalising IP
    addresses. It handles protocol detection (IPv4/IPv6), filters non-global
    addresses in production mode, integrates with whitelist checking via
    callbacks, and supports test mode for development.

    Key behaviours:
        - IPv4 addresses are validated and returned as-is if global
        - IPv6 addresses are converted to networks (default /112 mask)
        - Local/private addresses are rejected in production mode
        - Whitelist callback integration for filtering
        - Test mode (cf.TESTING) allows local addresses

    Attributes:
        cf: Config instance for configuration access
        error_name: Prefix string for error/info log messages (e.g., 'Blacklist:')
        addfn: Dict mapping protocol names to address constructor functions
        netfn: Dict mapping protocol names to network constructor functions
        ipname: Dict mapping protocol names to human-readable names

    Example:
        # Basic usage
        normalise = NormaliseAddress(cf, error_name='Blacklist')
        ipv4 = normalise.normal('198.51.100.1')  # Returns '198.51.100.1'
        ipv6 = normalise.normal('2001:db8::1')   # Returns '2001:db8::/112'

        # With whitelist checking
        from .whitelistcheck import WhiteListCheck
        wlc = WhiteListCheck(cf, normalise)
        addr = normalise.normal('203.0.113.50', is_white=wlc.is_white)

    Note:
        - Shared instances of this class are often passed to other components
        - The error_name can be changed after construction (e.g., in WhiteListCheck)
        - All methods log informational messages about filtering decisions
    """

    # Class-level mappings for protocol-specific functions
    addfn: dict[str, type[IPv4Address] | type[IPv6Address]] = {
        'ip':  ipaddress.IPv4Address,
        'ip6': ipaddress.IPv6Address
    }
    netfn: dict[str, type[IPv4Network] | type[IPv6Network]] = {
        'ip':  ipaddress.IPv4Network,
        'ip6': ipaddress.IPv6Network
    }
    ipname: dict[str, str] = {
        'ip': 'IPv4',
        'ip6': 'IPv6'
    }

    def __init__(self, cf: Config, error_name: str = "") -> None:
        """Initialize NormaliseAddress with config and error prefix.

        Args:
            cf: Config instance for accessing configuration values
            error_name: Prefix for log messages (e.g., 'Blacklist', 'Whitelist').
                       Automatically appended with ':' if non-empty.

        Example:
            # Create with error context
            normalise = NormaliseAddress(cf, error_name='Blacklist')
            # Log messages will be prefixed with 'Blacklist:'

            # Create without error context
            normalise = NormaliseAddress(cf)
            # Log messages will have no prefix
        """
        self.cf: Config = cf
        self.error_name: str = ''
        if error_name != '':
            self.error_name = f'{error_name}:'

    def normal(
        self,
        ipstr: str,
        is_white: Callable[[str, IpAddressType], bool] | None = None
    ) -> str | None:
        """Normalize IP address string and return as string.

        This is the main entry point for string-based IP normalisation. It
        automatically detects the protocol (IPv4 vs IPv6) by checking for ':',
        validates the address, and returns a normalised string representation.

        Args:
            ipstr: IP address string to normalise (e.g., '192.0.2.1' or '2001:db8::1')
            is_white: Optional callback to check if IP is whitelisted.
                     Signature: is_white(proto, ipaddr) -> bool
                     If returns True, the address is ignored (returns None).

        Returns:
            Normalized IP address as string, or None if the address should be
            ignored (local address, whitelisted, or invalid).

        Example:
            normalise = NormaliseAddress(cf, error_name='Blacklist')

            # IPv4 normalisation
            addr = normalise.normal('192.0.2.100')  # '192.0.2.100'

            # IPv6 normalisation (becomes /112 network)
            addr = normalise.normal('2001:db8::1')  # '2001:db8::/112'

            # Local address filtered in production
            addr = normalise.normal('192.168.1.1')  # None

            # With whitelist callback
            def is_white_cb(proto, ipaddr):
                return ipaddr in whitelist
            addr = normalise.normal('203.0.113.1', is_white=is_white_cb)

        Note:
            - Protocol is auto-detected: ':' in string → IPv6, else IPv4
            - Returns None for local/private addresses in production mode
            - Returns None if validation fails or whitelist callback returns True
        """
        proto = 'ip'
        if ':' in ipstr:
            proto = 'ip6'

        ipaddr = self.normal_ipaddr(proto, ipstr, is_white=is_white)
        return None if ipaddr is None else str(ipaddr)

    def normal_ipaddr(
        self,
        proto: str,
        ipstr: str,
        is_white: Callable[[str, IpAddressType], bool] | None = None
    ) -> IpAddressType | None:
        """Normalize IP address string and return as ipaddress object.

        This method delegates to either the production or test mode handler
        based on the presence of cf.TESTING attribute. Production mode filters
        out local/non-global addresses, while test mode allows them.

        Args:
            proto: Protocol identifier ('ip' for IPv4, 'ip6' for IPv6)
            ipstr: IP address string to normalise
            is_white: Optional callback to check if IP is whitelisted.
                     Signature: is_white(proto, ipaddr) -> bool

        Returns:
            IPv4Address, IPv4Network, IPv6Address, or IPv6Network object,
            or None if the address should be ignored.

        Example:
            normalise = NormaliseAddress(cf, error_name='Blacklist')

            # Get ipaddress object for IPv4
            addr = normalise.normal_ipaddr('ip', '198.51.100.1')
            # Returns: IPv4Address('198.51.100.1')

            # Get ipaddress object for IPv6 (becomes network)
            addr = normalise.normal_ipaddr('ip6', '2001:db8::1')
            # Returns: IPv6Network('2001:db8::/112')

        Note:
            - Most callers should use normal() for string-to-string conversion
            - This method is useful when you need the ipaddress object directly
            - Test mode is enabled by setting cf.TESTING attribute
        """
        if hasattr(self.cf, 'TESTING'):
            return self._normal_ipaddr_test(proto, ipstr, is_white)
        return self._normal_ipaddr_prod(proto, ipstr, is_white)

    def _normal_ipaddr_prod(
        self,
        proto: str,
        ipstr: str,
        is_white: Callable[[str, IpAddressType], bool] | None = None
    ) -> IpAddressType | None:
        """Production mode IP normalisation - filters non-global addresses.

        This is the production mode handler that enforces strict filtering:
        1. Creates ipaddress object via make_ipaddr()
        2. Checks if address is globally routable (is_global property)
        3. If global, checks whitelist callback (if provided)
        4. Returns address only if global and not whitelisted

        Args:
            proto: Protocol identifier ('ip' for IPv4, 'ip6' for IPv6)
            ipstr: IP address string to normalise
            is_white: Optional whitelist checking callback

        Returns:
            IPv4Address, IPv4Network, IPv6Address, or IPv6Network object,
            or None if address is local, whitelisted, or invalid.

        Example:
            # Called internally by normal_ipaddr() in production mode
            normalise = NormaliseAddress(cf, error_name='Blacklist')
            addr = normalise._normal_ipaddr_prod('ip', '192.0.2.100')
            # Returns: IPv4Address('192.0.2.100')

            # Local address is filtered
            addr = normalise._normal_ipaddr_prod('ip', '192.168.1.1')
            # Logs: "Blacklist: Local address 192.168.1.1 ignored"
            # Returns: None

        Note:
            - Local/private addresses (RFC1918, etc.) return None
            - Whitelisted addresses return None
            - Logs informational messages about filtering decisions
        """
        ipaddr = self.make_ipaddr(proto, ipstr)
        if ipaddr is None:
            return None
        if ipaddr.is_global:
            if is_white is not None \
               and is_white(proto, ipaddr):
                log.info('%s Whitelisted address %s ignored', self.error_name, ipaddr)
                return None
            # falls out
        else:
            log.info('%s Local address %s ignored', self.error_name, ipaddr)
            return None

        return ipaddr

    def _normal_ipaddr_test(
        self,
        proto: str,
        ipstr: str,
        is_white: Callable[[str, IpAddressType], bool] | None = None
    ) -> IpAddressType | None:
        """Test mode IP normalisation - allows local addresses.

        This is the test mode handler that skips the is_global check, allowing
        local/private addresses to be used for development and testing:
        1. Creates ipaddress object via make_ipaddr()
        2. Only checks whitelist callback (if provided)
        3. Returns address even if it's local/private

        Test mode is activated by setting cf.TESTING attribute, typically during
        unit testing or development.

        Args:
            proto: Protocol identifier ('ip' for IPv4, 'ip6' for IPv6)
            ipstr: IP address string to normalise
            is_white: Optional whitelist checking callback

        Returns:
            IPv4Address, IPv4Network, IPv6Address, or IPv6Network object,
            or None if address is whitelisted or invalid.

        Example:
            # Called internally by normal_ipaddr() when cf.TESTING exists
            cf.TESTING = True  # Enable test mode
            normalise = NormaliseAddress(cf, error_name='Test')

            # Local address is allowed in test mode
            addr = normalise._normal_ipaddr_test('ip', '192.168.1.1')
            # Returns: IPv4Address('192.168.1.1')

            # Still respects whitelist
            addr = normalise._normal_ipaddr_test('ip', '192.168.1.1',
                                                 is_white=lambda p, a: True)
            # Logs: "Test: Whitelisted address 192.168.1.1 ignored"
            # Returns: None

        Note:
            - Local/private addresses are accepted (unlike production mode)
            - Whitelist checking still applies
            - Use only for testing, not in production
        """
        ipaddr = self.make_ipaddr(proto, ipstr)
        if ipaddr is None:
            return None
        if is_white is not None \
           and is_white(proto, ipaddr):
            log.info('%s Whitelisted address %s ignored', self.error_name, ipaddr)
            return None

        return ipaddr


    def make_ipaddr(self, proto: str, ipstr: str) -> IpAddressType | None:
        """Create ipaddress object from string with protocol-specific handling.

        This method creates an appropriate ipaddress object based on the protocol
        and input format. Key behaviours:
        - IPv4 addresses become IPv4Address objects
        - IPv6 addresses become IPv6Network objects with configurable mask
        - CIDR notation (/) creates network objects for both protocols
        - IPv6 conversion to networks uses cf.default_ipv6_mask (default /112)

        Args:
            proto: Protocol identifier ('ip' for IPv4, 'ip6' for IPv6)
            ipstr: IP address string, optionally with CIDR notation

        Returns:
            IPv4Address, IPv4Network, IPv6Address, or IPv6Network object,
            or None if the string cannot be parsed.

        Example:
            normalise = NormaliseAddress(cf, error_name='Blacklist')

            # IPv4 address (no CIDR)
            addr = normalise.make_ipaddr('ip', '192.0.2.100')
            # Returns: IPv4Address('192.0.2.100')

            # IPv4 network with CIDR
            net = normalise.make_ipaddr('ip', '192.0.2.0/24')
            # Returns: IPv4Network('192.0.2.0/24')

            # IPv6 address without CIDR (becomes /112 network)
            addr = normalise.make_ipaddr('ip6', '2001:db8::1')
            # Returns: IPv6Network('2001:db8::/112')

            # IPv6 with explicit CIDR
            net = normalise.make_ipaddr('ip6', '2001:db8::/64')
            # Returns: IPv6Network('2001:db8::/64')

        Note:
            - strict=False allows non-zero host bits in network addresses
            - IPv6 addresses are always converted to networks (not addresses)
            - The default /112 mask for IPv6 can be configured
            - Validation errors are logged with error_name prefix
        """
        addfn = self.addfn[proto]
        netfn = self.netfn[proto]
        ipname = self.ipname[proto]

        ipaddr: IpAddressType
        try:
            if '/' in ipstr:
                ipaddr = netfn(ipstr, strict=False)  # type: ignore[assignment]
            else:
                addr = addfn(ipstr)
                if proto == 'ip6':
                    ipaddr = netfn((addr, self.cf.default_ipv6_mask),
                                   strict=False)  # type: ignore[assignment]
                else:
                    ipaddr = addr  # type: ignore[assignment]
        except ValueError as e:
            log.error('%s Problem converting %s address %s - %s',
                      self.error_name, ipname, ipstr, str(e))
            return None
        return ipaddr

    def is_network(self, proto: str, ipaddr: IpAddressType) -> bool:
        """Check if ipaddress object is a network type.

        This method determines whether an ipaddress object represents a network
        (IPv4Network or IPv6Network) rather than a single address (IPv4Address
        or IPv6Address).

        Args:
            proto: Protocol identifier ('ip' for IPv4, 'ip6' for IPv6)
            ipaddr: IP address or network object to check

        Returns:
            True if ipaddr is an IPv4Network or IPv6Network, False otherwise.

        Example:
            normalise = NormaliseAddress(cf)

            # Check IPv4 address vs network
            addr = IPv4Address('192.0.2.100')
            normalise.is_network('ip', addr)  # False

            net = IPv4Network('192.0.2.0/24')
            normalise.is_network('ip', net)   # True

            # Check IPv6 network
            addr = IPv6Network('2001:db8::/112')
            normalise.is_network('ip6', addr)  # True

        Note:
            - Uses isinstance() check against protocol-specific network class
            - IPv6 addresses from make_ipaddr() are always networks
            - Useful for distinguishing single IPs from CIDR blocks
        """
        return isinstance(ipaddr, (self.netfn[proto],))
