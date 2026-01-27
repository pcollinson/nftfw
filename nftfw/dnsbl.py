"""DNS Blacklist (DNSBL) lookup support for nftfw.

This module provides DNS-based blacklist checking functionality for nftfwedit.
It queries public DNS blacklist services to determine if IP addresses are
listed as sources of spam, abuse, or malicious activity.

**Purpose:**

DNS blacklists (also called RBLs - Real-time Blackhole Lists) are databases
of IP addresses that have been reported for sending spam or engaging in other
abusive behaviour. This module checks if an IP is listed in configured DNSBLs.

**Configuration:**

Blacklist services are configured in config.ini under [Nftfwedit] section.
Each entry specifies a name and lookup domain:

    [Nftfwedit]
    SpamHaus=zen.spamhaus.org
    Barracuda=b.barracudacentral.org
    SpamCop=bl.spamcop.net

**Requirements:**

Requires python3-dnspython package:
    sudo apt install python3-dnspython

Also recommended to run a caching nameserver for performance.

**Important Notes:**

Spamhaus Restrictions
    Spamhaus lookups will not work with some public DNS resolvers (like
    8.8.8.8). They return error values instead of NXDOMAIN. Use a local
    resolver or ISP DNS.

Match Codes
    Most DNSBLs return 127.0.0.2 for a positive match. Spamhaus uses
    multiple return codes (127.0.0.2-127.0.0.4, 127.0.0.9-127.0.0.11)
    for different listing reasons.

**Lookup Process:**

1. Convert IP to reverse DNS pointer format
2. Append DNSBL domain to reverse pointer
3. Query for A record (positive match if exists)
4. Validate return code matches expected values
5. Query for TXT record to get listing reason

**Integration:**

Used by nf_edit_print.PrintInfo to display DNSBL status when printing IP
information in nftfwedit.

**Related Modules:**
    - nf_edit_print: Displays DNSBL results
    - nftfwedit: Main database editor that uses this module
    - config: Configuration management

Example:
    Check IP against DNSBLs::\n
        from nftfw.config import Config
        from nftfw.dnsbl import Dnsbl\n
        cf = Config()
        dnsbl = Dnsbl(cf)
        if dnsbl.isinstalled():
            results = dnsbl.lookup('192.0.2.1')
            for name, inlist, message in results:
                if inlist:
                    print(f"{name}: {message}")
"""
from __future__ import annotations

import ipaddress
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .config import Config
    from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network

class Dnsbl:
    """DNS Blacklist lookup for IP addresses.

    This class provides DNS-based blacklist checking by querying configured
    DNSBL services. Handles both IPv4 and IPv6 addresses with support for
    CIDR notation.

    **Attributes:**
        cf: Config instance with DNSBL configuration
        lists: Dict mapping lowercase DNSBL names to lookup domains
        default_match: Default return codes indicating positive match
        special_match: Custom return codes for specific DNSBLs (e.g., Spamhaus)
        match_values: Currently active match codes
        resolver: DNS resolver instance (from dnspython)
        NXDOMAIN: NXDOMAIN exception class (from dnspython)

    **Methods:**
        isinstalled(): Check if any DNSBLs are configured
        lookup(): Check IP against all configured DNSBLs
        dnslookup(): Check IP against a single DNSBL

    Example:
        Query all configured DNSBLs::\n
            cf = Config()
            dnsbl = Dnsbl(cf)
            results = dnsbl.lookup('192.0.2.1')
            for name, found, msg in results:
                print(f"{name}: {found} - {msg}")
    """

    #pylint: disable=invalid-name
    # complaint about cf and NXDOMAIN

    def __init__(self, cf: Config) -> None:
        """Initialize DNSBL checker with configuration.

        Loads DNSBL services from configuration and sets up DNS resolver.
        If dnspython is not installed, clears the lists and prints installation
        instructions.

        Args:
            cf: Config instance with DNSBL configuration in [Nftfwedit] section

        Note:
            Requires python3-dnspython package. If not installed, all lookups
            will be disabled and an error message printed.

        Example:
            Initialize DNSBL checker::

                cf = Config()
                dnsbl = Dnsbl(cf)
                if dnsbl.isinstalled():
                    results = dnsbl.lookup('192.0.2.1')
        """
        self.cf: Config = cf
        self.lists: dict[str, str] = {}

        # match codes from DNSBLs
        self.default_match: tuple[str, ...] = ('127.0.0.2', )
        # Zen values
        self.special_match: dict[str, tuple[str, ...]] = {
            'spamhaus': ('127.0.0.2', '127.0.0.3', '127.0.0.4',
                        '127.0.0.9', '127.0.0.10', '127.0.0.11'),
        }
        self.match_values: tuple[str, ...] = self.default_match

        # get possible lookups from config
        for k, v in cf.parser['Nftfwedit'].items():
            self.lists[k.lower()] = v

        try:
            # Import here because the module may not be installed on the system
            # but pylint will complain on bookworm with import-outside-toplevel
            # pylint: disable=import-outside-toplevel
            import dns.resolver
            self.resolver = dns.resolver.Resolver()
            self.NXDOMAIN = dns.resolver.NXDOMAIN
        except ImportError:
            self.lists = {}
            print("Installation of python3-dnspython is required, run:")
            print("sudo apt install python3-dnspython")
            print("It's also recommended to run a caching nameserver")

    def isinstalled(self) -> bool:
        """Check if any DNSBL services are configured.

        Returns:
            True if at least one DNSBL service is configured in [Nftfwedit]
            section, False otherwise.

        Example:
            Check before performing lookups::

                dnsbl = Dnsbl(cf)
                if dnsbl.isinstalled():
                    results = dnsbl.lookup('192.0.2.1')
                else:
                    print("No DNSBL services configured")
        """
        return any(self.lists)

    def lookup(self, my_ip: str) -> list[tuple[str, bool, str]]:
        """Look up IP address in all configured DNSBL services.

        Queries each configured DNSBL service to check if the IP address is
        listed. Handles CIDR notation by converting to network address.

        Args:
            my_ip: IP address to check (IPv4 or IPv6, may include CIDR notation)

        Returns:
            List of tuples, one per DNSBL service:
                - [0] str: Name of DNSBL service (lowercase)
                - [1] bool: True if IP is listed in this DNSBL
                - [2] str: Message from DNSBL (listing reason if found, error/status otherwise)

        Example:
            Query all configured DNSBLs::

                dnsbl = Dnsbl(cf)
                results = dnsbl.lookup('192.0.2.1')
                for name, listed, message in results:
                    if listed:
                        print(f"Listed in {name}: {message}")
                    else:
                        print(f"Not in {name}")
        """
        result: list[tuple[str, bool, str]] = []
        # in case user has supplied form from blacklist.d (| instead of /)
        my_ip = my_ip.replace('|', '/')

        for name, domain in self.lists.items():
            (status, verbose) = self.dnslookup(name, domain, my_ip)
            app = (name, status, verbose)
            result.append(app)
        return result

    def dnslookup(self, name: str, domain: str, my_ip: str) -> tuple[bool, str]:
        """Look up single IP address in one DNSBL service.

        Converts IP to reverse DNS format, queries for A record (positive match),
        validates return code, and retrieves TXT record with listing reason.

        Args:
            name: Lowercase DNSBL service name (e.g., 'spamhaus')
            domain: DNSBL lookup domain (e.g., 'zen.spamhaus.org')
            my_ip: IP address to check (IPv4 or IPv6, may include CIDR)

        Returns:
            Tuple of (found, message):
                - found (bool): True if IP is listed in this DNSBL
                - message (str): Listing reason if found, status/error otherwise

        Note:
            Uses service-specific match codes. Most DNSBLs return 127.0.0.2
            for positive matches. Spamhaus uses multiple codes (127.0.0.2-4,
            127.0.0.9-11) for different listing reasons.

        Example:
            Check single DNSBL::

                found, msg = dnsbl.dnslookup('spamhaus', 'zen.spamhaus.org', '192.0.2.1')
                if found:
                    print(f"Listed: {msg}")
        """
        # Convert CIDR notation to network address if needed
        if '/' in my_ip:
            net = ipaddress.ip_network(my_ip, strict=False)
            ip = net.network_address
        else:
            ip = ipaddress.ip_address(my_ip)

        # Build reverse DNS query
        reverse = ip.reverse_pointer
        ma = re.match(r'^(.*)(in-addr\.arpa|ip6\.arpa)$', reverse)
        if ma is None:
            return False, ""
        query = ma.group(1) + domain

        # Set up expected match values for this DNSBL
        match_value = self.default_match
        if name in self.special_match:
            match_value = self.special_match[name]

        try:
            # Perform A record lookup - NXDOMAIN exception means not listed
            answers = self.resolver.resolve(query, "A")
            # No exception means IP is listed - verify return code
            if len(answers) == 1 and \
               answers[0].address not in match_value:
                return False, f'{my_ip} lookup fail for {domain}'

            # Get TXT record with listing reason
            answer_txt = self.resolver.resolve(query, "TXT")
            result = f'{my_ip} in {domain} ({answers[0]}: {answer_txt[0]})'
            return True, result
        except self.NXDOMAIN:
            return False, f'{my_ip} not in {domain}'
        except Exception as exc:  # pylint: disable=broad-exception-caught
            return False, str(exc)
