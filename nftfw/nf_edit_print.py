"""Pretty printing of IP address information for nftfwedit.

This module provides the PrintInfo class for displaying detailed information
about IP addresses in the nftfw blacklist database. It integrates data from
multiple sources to provide a comprehensive view of each IP address.

**Information Sources:**

Database (fwdb)
    Pattern matches, ports, timestamps, match counts, incidents

Blacklist Directory
    Active blacklist status (blacklisted or not, .auto files)

DNS Reverse Lookup
    Hostname, aliases, and related IP addresses

GeoIP2 (optional)
    Country name and ISO code

DNSBL (optional)
    DNS-based blacklist status (Spamhaus, etc.)

**Output Format:**

The print_ip() method displays all available information in a formatted
two-column layout:

    IP:         192.168.1.100
    Hostname:   scanner.example.com
    Active:     Blacklisted as 192.168.1.100.auto
    Database:   Found
    Pattern:    sshd
    Ports:      ssh (22)
    Latest:     2024-01-15 10:30:00
    First:      2024-01-10 08:15:00
    Duration:   5 days
    Matches:    150 - 30/day
    Incidents:  10 - 2/day
    Country:    United States (US)

**Related Modules:**
    - nftfwedit: Main database editor that uses this module
    - fwdb: Database access for IP information
    - geoipcountry: GeoIP2 country lookup
    - dnsbl: DNS blacklist checking
    - nftfwls: Provides datefmt() for timestamp formatting
    - stats: Provides duration() and frequency() formatting

Example:
    Display information about an IP address::

        from nftfw.config import Config
        from nftfw.nf_edit_print import PrintInfo

        cf = Config()
        printer = PrintInfo(cf)
        printer.print_ip("192.168.1.100", showhostinfo=True)

    Check if IP is actively blacklisted::

        filename = printer.check_online("192.168.1.100")
        if filename:
            print(f"Blacklisted as: {filename}")
"""
from __future__ import annotations

from socket import gethostbyaddr, herror, getservbyport
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .nftfwls import datefmt
from .stats import duration, frequency
from .nf_edit_validate import validate_and_return_ip
from .fwdb import FwDb
from .geoipcountry import GeoIPCountry
from .dnsbl import Dnsbl

if TYPE_CHECKING:
    from .config import Config

class PrintInfo:
    """Display detailed information about IP addresses.

    This class integrates data from multiple sources (database, filesystem,
    DNS, GeoIP2, DNSBL) to provide comprehensive information about IP addresses
    in the nftfw blacklist system.

    **Attributes:**
        cf: Config instance
        db: FwDb instance for database access (opened read-only)
        geoip: GeoIPCountry instance for country lookups
        dnsbl: Dnsbl instance for DNS blacklist checking

    **Methods:**
        print_ip(): Display all information about an IP address
        check_online(): Check if IP is actively blacklisted
        print_hostinfo(): Display DNS reverse lookup information
        format_item(): Format database record for display
        ports_by_name(): Convert port numbers to service names
        format_freq(): Format counts with frequency information

    Example:
        Display IP information with all available data::

            from nftfw.config import Config
            from nftfw.nf_edit_print import PrintInfo

            cf = Config()
            printer = PrintInfo(cf)

            # Full display with hostname lookup
            printer.print_ip("192.168.1.100", showhostinfo=True)

            # Quick display without hostname lookup
            printer.print_ip("10.0.0.50")
    """

    cf: Config
    db: FwDb
    geoip: GeoIPCountry
    dnsbl: Dnsbl

    def __init__(self, cf: Config) -> None:
        """Initialise PrintInfo with configuration.

        Opens database for read-only access and initialises optional GeoIP2
        and DNSBL lookup services.

        Args:
            cf: Config instance with paths and settings

        Returns:
            None

        Example:
            Standard initialization::

                from nftfw.config import Config

                cf = Config()
                printer = PrintInfo(cf)
        """
        self.cf = cf
        # open and retain classes we may use
        self.db = FwDb(cf, createdb=False)
        self.geoip = GeoIPCountry()
        self.dnsbl = Dnsbl(cf)

    def check_online(self, ipstr: str) -> str | None:
        """Check if IP address is actively blacklisted.

        Checks the blacklist directory for files matching the IP address.
        Handles both regular blacklist files and .auto files (automatically
        created by the blacklist system).

        **File Name Conversion:**

        CIDR notation is converted from / to | for filesystem compatibility:
            - "192.168.1.0/24" becomes "192.168.1.0|24"

        **Search Order:**

        1. Exact match: IP address filename
        2. Auto match: IP address with .auto suffix

        Args:
            ipstr: IP address string (can include CIDR notation)

        Returns:
            Filename if IP is actively blacklisted, None otherwise

        Example:
            Check if various IPs are blacklisted::

                printer = PrintInfo(cf)

                # Regular blacklist file
                result = printer.check_online("192.168.1.100")
                # Returns: "192.168.1.100" if exists, None otherwise

                # Auto blacklist file
                result = printer.check_online("10.0.0.50")
                # Returns: "10.0.0.50.auto" if exists

                # CIDR notation (converted to pipe)
                result = printer.check_online("192.168.1.0/24")
                # Looks for: "192.168.1.0|24" or "192.168.1.0|24.auto"
        """
        blacklistpath: Path = self.cf.etcpath('blacklist')
        if '/' in ipstr:
            ipstr = ipstr.replace('/', '|')
        filepath: Path = blacklistpath / ipstr
        if filepath.exists():
            return str(filepath.name)
        auto: str = ipstr + '.auto'
        filepath = blacklistpath / auto
        if filepath.exists():
            return str(filepath.name)
        return None

    def print_ip(self, ipaddress: str, showhostinfo: bool = False) -> None:
        """Print comprehensive information about an IP address.

        Displays information from multiple sources in a formatted two-column
        layout. Data includes validation, hostname, blacklist status, database
        records, GeoIP2 location, and DNSBL status.

        **Information Displayed:**

        Always shown:
            - IP address (validated and normalised)
            - Active blacklist status (blacklisted or not)
            - Database record (if found)

        Optional (if available):
            - Hostname and aliases (if showhostinfo=True and DNS succeeds)
            - Pattern that matched this IP
            - Ports associated with matches
            - First and last seen timestamps
            - Duration of activity
            - Match and incident counts with frequency
            - Country from GeoIP2 (if GeoIP2 installed)
            - DNSBL listings (if DNSBL configured)

        Args:
            ipaddress: IP address string to display (any format accepted)
            showhostinfo: If True, perform DNS reverse lookup for hostname

        Returns:
            None. Prints directly to stdout. Returns silently if IP is invalid.

        Example:
            Display with all information::

                printer = PrintInfo(cf)
                printer.print_ip("192.168.1.100", showhostinfo=True)

            Display without DNS lookup (faster)::

                printer.print_ip("10.0.0.50")

            Typical output::

                IP:         192.168.1.100
                Hostname:   scanner.example.com
                Active:     Blacklisted as 192.168.1.100.auto
                Pattern:    sshd
                Ports:      ssh
                Latest:     2024-01-15 10:30:00
                First:      2024-01-10 08:15:00
                Duration:   5 days
                Matches:    150 - 30/day
                Incidents:  10 - 2/day
                Country:    United States (US)
        """
        ipstr: str | None = validate_and_return_ip(ipaddress)
        if ipstr is None:
            return

        fmt: str = '%-10s %s'
        print(fmt % ('IP:', str(ipstr)))

        # gethostbyaddr information
        if showhostinfo:
            self.print_hostinfo(fmt, ipstr)

        online: str | None = self.check_online(ipstr)
        if online is not None:
            print(fmt % ('Active:', f'Blacklisted as {online}'))
        else:
            print(fmt % ('Active:', 'No'))

        # lookup in database
        lookup: list[dict[str, Any]] = self.db.lookup_by_ip(ipstr)
        if not any(lookup):
            print(fmt % ('Database:', 'Not found in database'))
        else:
            self.format_item(fmt, lookup[0])


        # GeoIP2 information
        if self.geoip.isinstalled():
            country: str | None
            iso: str | None
            country, iso = self.geoip.lookup(ipstr)
            if country is not None:
                print(fmt % ('Country:', f'{country} ({iso})'))

        # DNSBL information
        if self.dnsbl.isinstalled():
            dnsbl_lookup = self.dnsbl.lookup(ipstr)
            if any(dnsbl_lookup):
                for name, inlist, verbose in dnsbl_lookup:
                    if inlist:
                        print(fmt % (name.capitalize()+':', verbose))

    @staticmethod
    def print_hostinfo(fmt: str, ipstr: str) -> None:
        """Print DNS reverse lookup information.

        Performs a reverse DNS lookup to retrieve hostname, aliases, and
        related IP addresses for the given IP. Displays results in the
        specified format.

        **DNS Lookup:**

        Uses socket.gethostbyaddr() to query DNS PTR records. This can be
        slow if DNS is unavailable or the IP has no reverse DNS entry.

        **Information Displayed:**

        Hostname
            Primary hostname (PTR record)

        Alias
            Comma-separated list of CNAME aliases

        Other IPs
            Other IP addresses associated with the same hostname (excluding
            the queried IP itself)

        Args:
            fmt: Format string for output (e.g., '%-10s %s')
            ipstr: IP address string to look up

        Returns:
            None. Prints directly to stdout.

        Example:
            Display hostname information::

                fmt = '%-10s %s'
                PrintInfo.print_hostinfo(fmt, "8.8.8.8")

            Typical output::

                Hostname:   dns.google
                Other IPs:  8.8.4.4

            Failed lookup::

                Hostname:   Unknown
        """
        try:
            host: str
            alias: list[str]
            ips: list[str]
            host, alias, ips = gethostbyaddr(str(ipstr))
            if host is not None:
                print(fmt % ('Hostname:', host))
            if any(alias):
                print(fmt % ('Alias:', ', '.join(alias)))
            if any(ips):
                rem: list[str] = [i for i in ips if i != ipstr]
                if any(rem):
                    print(fmt % ('Other IPs:', ', '.join(rem)))
        except herror:
            print(fmt % ('Hostname:', 'Unknown'))

    def format_item(self, fmt: str, current: dict[str, Any]) -> None:
        """Format and display database record information.

        Displays pattern, ports, timestamps, duration, and match/incident
        statistics from a database record. Formats timestamps using the
        configured date format and includes frequency calculations.

        **Fields Displayed:**

        Pattern
            Pattern name that matched this IP

        Ports
            Port numbers converted to service names where possible

        Forced to 'all'
            Note if ports were forced to 'all' in firewall (useall flag)

        Latest/First
            Last and first seen timestamps (formatted per config)

        Duration
            Time span between first and last seen (if different)

        Matches
            Total match count with frequency (e.g., "150 - 30/day")

        Incidents
            Total incident count with frequency (e.g., "10 - 2/day")

        Args:
            fmt: Format string for output (e.g., '%-10s %s')
            current: Database record dict with keys: pattern, ports, useall,
                    last, first, matchcount, incidents

        Returns:
            None. Prints directly to stdout.

        Example:
            Format a database record::

                record = db.lookup_by_ip("192.168.1.100")[0]
                printer.format_item('%-10s %s', record)

            Typical output::

                Pattern:    sshd
                Ports:      ssh
                Latest:     2024-01-15 10:30:00
                First:      2024-01-10 08:15:00
                Duration:   5 days
                Matches:    150 - 30/day
                Incidents:  10 - 2/day
        """
        cf: Config = self.cf
        config: dict[str, Any] = cf.get_ini_values_by_section('Nftfwls')
        date_fmt: str = str(config['date_fmt'])

        print(fmt % ('Pattern:', current['pattern']))
        portlist: str = self.ports_by_name(current['ports'])
        print(fmt % ('Ports:', portlist))
        if current['useall']:
            print(fmt % ('', "Forced to 'all' in firewall"))
        print(fmt % ("Latest:", datefmt(date_fmt, current['last'])))
        print(fmt % ("First:", datefmt(date_fmt, current['first'])))
        first: int = current['first']
        last: int = current['last']
        if first < last:
            print(fmt % ("Duration:", duration(first, last)))
        print(fmt % ("Matches:", self.format_freq(first, last, current['matchcount'])))
        print(fmt % ("Incidents:", self.format_freq(first, last, current['incidents'])))

    @staticmethod
    def ports_by_name(ports: str) -> str:
        """Convert port numbers to service names.

        Converts a comma-separated list of port numbers to service names
        where possible using /etc/services lookup. Port numbers without
        known service names are kept as numbers.

        **Special Value:**

        "all" is returned unchanged (represents all ports)

        **Service Name Lookup:**

        Uses socket.getservbyport() to look up service names. If lookup
        fails, the port number is used instead.

        Args:
            ports: Comma-separated port numbers or "all"

        Returns:
            Comma-separated service names/port numbers, or "all"

        Example:
            Convert ports to names::

                # Known services
                result = PrintInfo.ports_by_name("22,80,443")
                # Returns: "ssh, http, https"

                # Mix of known and unknown
                result = PrintInfo.ports_by_name("22,9999")
                # Returns: "ssh, 9999"

                # Special value
                result = PrintInfo.ports_by_name("all")
                # Returns: "all"

                # Single port
                result = PrintInfo.ports_by_name("22")
                # Returns: "ssh"
        """
        if ports == 'all':
            return ports
        out: list[str] = []
        plist: list[str] = ports.split(',')
        for pno in plist:
            portno: str = pno.strip()
            try:
                serv: str = getservbyport(int(portno))
                out.append(serv)
            except OSError:
                out.append(portno)
        return ", ".join(out)

    @staticmethod
    def format_freq(first: int, last: int, val: int) -> str:
        """Format a value with frequency information.

        Formats a count value with an optional frequency calculation appended.
        Frequency is only shown if there's a time span (first < last) and
        multiple occurrences (val > 1).

        **Frequency Calculation:**

        Uses the frequency() function from stats module to calculate
        occurrences per time period (e.g., "30/day", "5/hour").

        **Format:**

        - Value only: "1"
        - Value with frequency: "150 - 30/day"

        Args:
            first: First timestamp (Unix epoch seconds)
            last: Last timestamp (Unix epoch seconds)
            val: Count value to display

        Returns:
            Formatted string with value and optional frequency

        Example:
            Format various counts::

                # Single occurrence (no frequency)
                result = PrintInfo.format_freq(1000, 2000, 1)
                # Returns: "1"

                # Multiple over time
                result = PrintInfo.format_freq(1000, 87400, 150)
                # Returns: "150 - 30/day" (assuming 1 day span)

                # Same timestamp (no frequency)
                result = PrintInfo.format_freq(1000, 1000, 100)
                # Returns: "100"

                # Two occurrences close together
                result = PrintInfo.format_freq(1000, 1100, 2)
                # Returns: "2 - 72/hour" (2 in 100 seconds)
        """
        freq: str = ''
        if first < last \
           and val > 1:
            freq = frequency(first, last, val)
            if freq != '':
                freq = ' - ' + freq
        return str(val) + freq
