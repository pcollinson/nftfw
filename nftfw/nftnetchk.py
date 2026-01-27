#!/usr/bin/python3
"""nftnetchk - Network checker utility for identifying redundant blacklist entries.

This module provides the nftnetchk command-line utility for analyzing IP addresses
in the nftfw blacklist database and identifying entries that are already covered by
network ranges in the blacknets.d directory. This helps clean up the database by
removing individual IPs that are redundant.

**Purpose:**

The utility checks each IP in the blacklist database against network ranges in
blacknets.d files. If an IP falls within a blacknet range, it's redundant because
the network-level blocking already covers it.

**Usage:**
    nftnetchk [-h] [-l]

**Options:**

-l, --list
    Output just the IP addresses that can be deleted (one per line).
    Suitable for piping to nftfwedit for batch deletion.

Default (no options)
    Display formatted table showing redundant IPs with their matching networks,
    source files, and database timestamps.

**Output Formats:**

List mode (-l)
    Simple list of IP addresses, one per line:
        192.168.1.100
        10.0.0.50
        2001:db8::1

Table mode (default)
    PrettyTable with columns:
        - IP: IP address from database
        - Found in: Blacknets file containing the matching network
        - Net: Network range that covers this IP
        - Latest: Most recent incident timestamp
        - First: First incident timestamp (or '-' if same as Latest)
        - Duration: Time span between First and Latest (or '-' if same)

**Workflow:**

1. Load network ranges from blacknets.d directory using NetReaderFromFiles
2. Load IP addresses from blacklist database with timestamps
3. For each database IP, check if it falls within any blacknet range
4. Display matches in requested format

**Integration:**

The utility integrates with multiple nftfw components:
    - netreader: Loads and parses blacknets.d files
    - fwdb: Database access for blacklist entries
    - stats: Duration formatting for time spans
    - config: Configuration management

**Related Modules:**
    - netreader: Network blacklist file reader
    - fwdb: Database access layer
    - stats: Time formatting utilities
    - config: Configuration management
    - nftfwedit: Database editor for removing redundant entries

Example:
    Show redundant IPs in table format::\n
        nftnetchk\n
    \n
    Generate list for batch deletion::\n
        nftnetchk -l | while read ip; do nftfwedit -d "$ip"; done\n
"""
from __future__ import annotations

import sys
import logging
import ipaddress
import datetime
import argparse
from typing import TYPE_CHECKING, Any, cast

from prettytable import PrettyTable
from .config import Config
from .netreader import NetReaderFromFiles
from .fwdb import FwDb
from .stats import duration

if TYPE_CHECKING:
    from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network

log = logging.getLogger('nftfw')

class NetsCheck:
    """Check IP addresses in database against blacknets.d network ranges.

    This class implements the core functionality of nftnetchk, checking each IP
    in the blacklist database to see if it's covered by network ranges in the
    blacknets.d directory. Maintains data structures for networks, source files,
    IPs, and timestamps.

    **Attributes:**
        cf: Config instance with paths and settings
        justlist: If True, output only IP addresses; if False, output full table
        nets: Dict mapping 'ip'/'ip6' to dict of {footprint: network_object}
        source: Dict mapping filename to list of footprint values
        iplist: List of IP address/network objects from database
        timedata: Dict mapping IP string to database record with timestamps

    **Methods:**
        get_blacknets(): Load network ranges from blacknets.d directory
        get_ips_from_db(): Load IP addresses and timestamps from database
        search_for_ip_match(): Find networks that cover a given IP
        footprint_search(): Find files containing a given footprint
        datefmt(): Format Unix timestamps as human-readable strings
        process(): Execute the complete analysis workflow

    Example:
        Run network check::\n
            cf = Config()
            checker = NetsCheck(cf, justlist=False)
            checker.process()  # Displays table of redundant IPs
    """

    cf: Config
    justlist: bool
    nets: dict[str, dict[int, IPv4Network | IPv6Network]] | None
    source: dict[str, list[int]] | None
    iplist: list[IPv4Address | IPv4Network | IPv6Address | IPv6Network]
    timedata: dict[str, dict[str, Any]]

    def __init__(self, cf: Config, justlist: bool) -> None:
        """Initialise NetsCheck with configuration and output mode.

        Args:
            cf: Config instance with paths and settings
            justlist: If True, output only IP addresses for deletion

        Returns:
            None

        Example:
            Create checker for table output::\n
                cf = Config()
                checker = NetsCheck(cf, justlist=False)

            Create checker for list output::\n
                checker = NetsCheck(cf, justlist=True)
        """

        self.cf = cf
        self.justlist = justlist
        # defined in get_blacknets
        self.nets: dict[str, dict[int, IPv4Network | IPv6Network]] | None = None
        self.source: dict[str, list[int]] | None = None
        # defined in get_ips_from_db
        self.iplist = []
        self.timedata = {}

    def get_blacknets(self) -> None:
        """Load network ranges from blacknets.d directory.

        Uses NetReaderFromFiles to load and parse all .nets files in the
        blacknets.d directory. Populates self.nets with network objects and
        self.source with file-to-footprint mappings.

        **Data Structures Populated:**

        self.nets
            Dict with keys 'ip' and 'ip6', each containing a dict mapping
            footprint (hash) to network object (IPv4Network or IPv6Network)

        self.source
            Dict mapping filename to list of footprint values found in that file

        **Version Check:**

        Requires nftfw v0.9.20+ for source attribute support. Exits with error
        message if older version detected.

        Returns:
            None. Populates self.nets and self.source attributes.

        Example:
            Load blacknets::\n
                checker = NetsCheck(cf, justlist=False)
                checker.get_blacknets()
                # Now checker.nets and checker.source are populated
        """

        netr: NetReaderFromFiles = NetReaderFromFiles(self.cf, 'blacknets')

        # self.nets is a hash with keys
        # ip and ip6
        # each values are hashes with
        # keys of the footprint value
        # and an argument of an IP4 or
        # IP6 network object
        # In practice, netr.nets only contains Network types, not Address types
        self.nets = netr.nets  # type: ignore[assignment]

        # self.source is a hash that
        # maps the filename to a list of
        # footprint values in the file
        try:
            getattr(netr, 'source')
            self.source = netr.source
        except AttributeError:
            print("Sorry, the version of 'netreader' doesn't have support for this script")
            print("You need version at least v0.9.20 of nftfw")
            sys.exit(1)

    def get_ips_from_db(self) -> None:
        """Load IP addresses and timestamps from blacklist database.

        Queries the database for all IP addresses with their first and last
        seen timestamps. Converts IP strings to ipaddress module objects for
        network matching. Populates self.iplist and self.timedata.

        **Processing:**

        1. Query database for ip, first, last columns
        2. Separate IPs with '/' (networks) from plain IPs (addresses)
        3. Convert plain IPs to IPv4Address/IPv6Address objects
        4. Convert CIDR IPs to IPv4Network/IPv6Network objects (strict=False)
        5. Combine into single list stored in self.iplist
        6. Build timedata dict for timestamp lookups

        **Data Structures Populated:**

        self.iplist
            List of IPv4Address, IPv4Network, IPv6Address, and IPv6Network
            objects from the database

        self.timedata
            Dict mapping IP string to database record dict with 'ip', 'first',
            and 'last' keys

        Returns:
            None. Populates self.iplist and self.timedata attributes.

        Example:
            Load database IPs::\n
                checker = NetsCheck(cf, justlist=False)
                checker.get_ips_from_db()
                # Now checker.iplist contains IP objects
                # and checker.timedata contains timestamp info
        """

        db: FwDb = FwDb(self.cf, createdb=False)
        results: list[dict[str, Any]] = db.lookup('blacklist',
                                                   what="ip,first,last",
                                                   orderby='last DESC')
        db.close()

        # results is a list of hash 'ip', 'first' and 'last' values
        iplist: list[str] = [elem['ip'] for elem in results]
        ips: list[IPv4Address | IPv6Address] = [
            ipaddress.ip_address(ip)
            for ip in iplist if '/' not in ip
        ]
        ipn: list[IPv4Network | IPv6Network] = [
            ipaddress.ip_network(ip, strict=False)
            for ip in iplist if '/' in ip
        ]
        self.iplist = ips + ipn

        # Make a hash indexed by ip
        # to print times on the output
        self.timedata = {elem['ip']: elem for elem in results}

    def search_for_ip_match(
            self, ipcheck: IPv4Address | IPv4Network | IPv6Address | IPv6Network
    ) -> list[list[int | IPv4Network | IPv6Network]]:
        """Find network ranges that cover the given IP address.

        Searches self.nets for network ranges that contain the specified IP
        address or network. Uses Python's 'in' operator for subnet matching.
        May return multiple matches if IP is covered by multiple networks.

        **IPv4 vs IPv6:**

        Automatically selects appropriate protocol based on ipcheck.version:
            - version 4: Searches self.nets['ip']
            - version 6: Searches self.nets['ip6']

        Args:
            ipcheck: IP address or network object to check

        Returns:
            List of [footprint, network_object] pairs for all matching networks.
            Empty list if no matches found.

        Example:
            Check if IP is covered::\n
                checker = NetsCheck(cf, justlist=False)
                checker.get_blacknets()
                ip = ipaddress.ip_address('192.168.1.100')
                matches = checker.search_for_ip_match(ip)
                # Returns: [[12345, IPv4Network('192.168.1.0/24')], ...]
        """

        out: list[list[int | IPv4Network | IPv6Network]] = []
        ipproto: str = 'ip'
        if ipcheck.version == 6:
            ipproto = 'ip6'
        # select appropriate set of values
        srchfor: dict[int, IPv4Network | IPv6Network] | None
        srchfor = self.nets[ipproto]  # type: ignore[index]
        if srchfor:
            # srch is list of hashes: {footprint: ipobject}
            for footprint, ipobj in srchfor.items():
                if ipcheck in ipobj:
                    out.append([footprint, ipobj])
        return out

    def footprint_search(self, footp: int) -> list[str]:
        """Find blacknets.d files containing the given footprint.

        Searches self.source dict to find which files contain a network with
        the specified footprint value. Used to identify the source file for
        a matching network range.

        Args:
            footp: Footprint (hash) value to search for

        Returns:
            List of filenames (without directory path) that contain the
            footprint. Empty list if not found in any file.

        Example:
            Find source files::\n
                checker = NetsCheck(cf, justlist=False)
                checker.get_blacknets()
                files = checker.footprint_search(12345)
                # Returns: ['spamhaus.nets', 'local_blocks.nets']
        """

        out: list[str] = []
        for fname, footplist in self.source.items():  # type: ignore[union-attr]
            if footp in footplist:
                out.append(fname)
        return out

    @staticmethod
    def datefmt(fmt: str, timeint: int) -> str:
        """Format Unix timestamp as human-readable date/time string.

        Converts Unix epoch timestamps to formatted date/time strings using
        strftime format codes. Centralized function for consistent date
        formatting throughout nftnetchk output.

        Args:
            fmt: strftime format string (from Nftfwls config section)
            timeint: Unix epoch timestamp (seconds since 1970-01-01)

        Returns:
            Formatted date/time string

        Example:
            Format timestamp::\n
                formatted = NetsCheck.datefmt('%Y-%m-%d %H:%M:%S', 1705318200)
                # Returns: "2024-01-15 10:30:00"
        """

        value: datetime.datetime = datetime.datetime.fromtimestamp(timeint)
        return value.strftime(fmt)

    def process(self) -> None:
        """Execute complete network checking workflow.

        Orchestrates the entire analysis by loading networks, loading database
        IPs, checking for matches, and displaying results in the requested
        format (list or table).

        **Workflow:**

        1. Load date_fmt from Nftfwls config section
        2. Load blacknets with get_blacknets()
        3. Load database IPs with get_ips_from_db()
        4. Initialize PrettyTable if not in list mode
        5. For each database IP:
           - Search for matching networks with search_for_ip_match()
           - For each match, find source files with footprint_search()
           - Display IP (list mode) or add table row (table mode)
        6. Print table if any matches found (table mode only)

        **Output:**

        List mode (--list)
            Prints just the IP addresses, one per line

        Table mode (default)
            Prints PrettyTable with columns: IP, Found in, Net, Latest,
            First, Duration

        Returns:
            None. Prints results directly to stdout.

        Example:
            Run complete analysis::\n
                checker = NetsCheck(cf, justlist=False)
                checker.process()
                # Displays table of redundant IPs
        """

        # We need the date format
        date_fmt: str = cast(str, self.cf.get_ini_value_from_section('Nftfwls', 'date_fmt'))
        # get blacknet data
        self.get_blacknets()
        # get ips from the database
        self.get_ips_from_db()

        pt: PrettyTable
        if not self.justlist:
            pt = PrettyTable()
            pt.field_names = ['IP', 'Found in', 'Net',
                              'Latest', 'First', "Duration"]

        haveptoutput: bool = False
        for ipobj in self.iplist:
            matchlist: list[list[int | IPv4Network | IPv6Network]]
            matchlist = self.search_for_ip_match(ipobj)
            for footprint, ipmatched in matchlist:
                filenames: list[str]
                filenames = self.footprint_search(int(footprint))  # type: ignore[arg-type]
                for filename in filenames:
                    if self.justlist:
                        print(f'{str(ipobj)}')
                    else:
                        haveptoutput = True
                        ip: str = str(ipobj)
                        firstst: str = self.datefmt(date_fmt, self.timedata[ip]['first'])
                        lastst: str = self.datefmt(date_fmt, self.timedata[ip]['last'])
                        dur: str
                        if firstst == lastst:
                            firstst = '-'
                            dur = '-'
                        else:
                            dur = duration(self.timedata[ip]['first'], self.timedata[ip]['last'])
                        pt.add_row([ip, filename, ipmatched, lastst, firstst, dur])

        if haveptoutput and not self.justlist:
            # set up format
            pt.align = 'l'
            print(pt)

def main() -> None:
    """Main entry point for nftnetchk command-line utility.

    Parses command-line arguments, initialises configuration with custom
    logging settings, creates NetsCheck instance, and executes the analysis.

    **Configuration:**

    1. Initialize Config with dosetup=False
    2. Read config.ini file
    3. Disable syslog logging (console only)
    4. Set custom log format: 'Error: %(message)s'
    5. Complete setup with cf.setup()

    **Logging:**

    Custom logging configuration for simpler output:
        - Syslog disabled (logsyslog=False)
        - Simple error format without timestamps or levels
        - Errors printed to console only

    **Error Handling:**

    - Config read error: Prints error and exits with code 1
    - Setup error: Logs critical message and exits with code 1

    Args:
        None. Parses sys.argv for command-line arguments.

    Returns:
        None. Exits with code 0 on success, 1 on error.

    Example:
        Normal invocation from command line::\n
            $ nftnetchk           # Show table of redundant IPs
            $ nftnetchk -l        # List IPs only
    """

    cf: Config = Config(dosetup=False)

    # Get the ini file setup
    # with no sys logging
    # and a private log format
    try:
        cf.readini()
    except AssertionError as e:
        print(f'Aborted: {str(e)}')
        sys.exit(1)
    # turn off logsyslog
    cf.set_logger(logsyslog=False)
    cf.set_ini_value_with_section('Logging', 'logfmt', 'Error: %(message)s')
    try:
        cf.setup()
    except AssertionError as e:
        log.critical('Aborted: Configuration problem: %s', str(e))
        sys.exit(1)

    ap: argparse.ArgumentParser = argparse.ArgumentParser(prog='nftnetchk')
    ap.add_argument('-l', '--list',
                    help='List the just ips that can be deleted',
                    action='store_true')

    args: argparse.Namespace = ap.parse_args()
    ck: NetsCheck = NetsCheck(cf, args.list)
    ck.process()
    sys.exit(0)

if __name__ == '__main__':

    main()
    sys.exit(0)
