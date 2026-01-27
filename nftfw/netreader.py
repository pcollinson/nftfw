"""Network blacklist reader with JSON caching for nftfw.

This module provides two classes for reading and managing network blacklists
from the blacknets.d directory. The system uses intelligent caching to avoid
re-processing static network lists on every firewall reload.

Key Features
------------
- Reads *.nets files containing CIDR network addresses
- Supports both IPv4 and IPv6 networks
- Handles IPv6-mapped IPv4 addresses (::ffff:x.x.x.x)
- JSON caching with mtime-based invalidation
- Automatic overlap elimination using ipaddress.collapse_addresses()
- Deduplication via footprint-based storage
- Comment support (# prefix)
- Source file tracking for debugging

File Format
-----------
*.nets files in blacknets.d directory contain:
- One CIDR network or IP address per line
- Comments starting with # (can be inline or full-line)
- Blank lines are ignored

Example .nets file::

    # Block specific malicious networks
    192.0.2.0/24        # Example network
    198.51.100.0/24
    2001:db8::/32       # Example IPv6 network
    203.0.113.42        # Single IP (auto-converted to /32)

Caching Mechanism
-----------------
The NetReader class maintains a JSON cache containing:
- File names and mtimes for change detection
- Processed IPv4 network list
- Processed IPv6 network list

Cache is invalidated when:
1. Cache file doesn't exist
2. Any source file mtime changes
3. New *.nets files appear
4. Existing files are deleted
5. User forces full install (cf.force_full_install)

Architecture
------------
NetReader (main class):
    - Manages cache lifecycle
    - Decides when to reload from files
    - Provides records dict for NetProcess

NetReaderFromFiles (worker class):
    - Parses *.nets files
    - Validates network addresses
    - Eliminates duplicates and overlaps
    - Converts IPv6-mapped IPv4 addresses
    - Returns clean network lists

Workflow::

    1. NetReader.__init__() called from fwmanage.py
    2. Check if cache exists and is valid
    3. If invalid: NetReaderFromFiles reads all *.nets files
    4. Process networks: parse → validate → deduplicate → collapse
    5. Save to JSON cache
    6. Populate records dict for NetProcess

Usage Example::

    from .config import Config
    from .netreader import NetReader

    cf = Config()
    cf.readini()
    cf.setup()

    # Read blacknets with caching
    nr = NetReader(cf, 'blacknets')

    # Access processed records
    if nr.records:
        print(f"Loaded {len(nr.cache['ip'])} IPv4 networks")
        print(f"Loaded {len(nr.cache['ip6'])} IPv6 networks")

    # Records structure for NetProcess
    # {'all': {'name': 'blacknets_set', 'ip': [...], 'ip6': [...]}}

See Also
--------
netprocess.py : Processes NetReader.records into nftables commands
listreader.py : Similar reader for blacklist.d/whitelist.d files
fwmanage.py : Main firewall manager that uses NetReader

"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast
import re
import ipaddress
import logging
from pathlib import Path
import json

if TYPE_CHECKING:
    from .config import Config

log = logging.getLogger('nftfw')

# Type alias for IP address/network objects
IpAddressType = (ipaddress.IPv4Address | ipaddress.IPv4Network |
                 ipaddress.IPv6Address | ipaddress.IPv6Network)


class NetReader:
    """Network blacklist reader with intelligent JSON caching.

    Manages the lifecycle of network blacklist data from blacknets.d directory.
    Uses JSON caching to avoid re-reading static files on every firewall reload.
    Automatically detects file changes via mtime tracking and rebuilds cache
    when needed.

    The cache is invalidated and rebuilt when:
    - Cache file doesn't exist
    - Any *.nets file mtime changes
    - New files appear in blacknets.d
    - Files are deleted from blacknets.d
    - User forces full install

    Attributes
    ----------
    cf : Config
        Configuration instance
    cachepath : Path
        Path to JSON cache file (usually /var/lib/nftfw/blacknets_cache)
    cache : dict[str, Any]
        Cache data structure:
        - 'files': dict[str, int] - filename → mtime mapping
        - 'ip': list[str] - IPv4 networks/addresses
        - 'ip6': list[str] - IPv6 networks/addresses
    records : dict[str, dict[str, Any]]
        Output records for NetProcess:
        - Key: 'all' (all networks use same nftables set)
        - Value: {'name': 'blacknets_set', 'ip': [...], 'ip6': [...]}

    Example
    -------
    Reading blacknets with automatic caching::

        from .config import Config
        from .netreader import NetReader

        cf = Config()
        nr = NetReader(cf, 'blacknets')

        # Check if any networks loaded
        if nr.records:
            print("Blacknets loaded successfully")
            if 'ip' in nr.records['all']:
                print(f"IPv4 networks: {len(nr.records['all']['ip'])}")
            if 'ip6' in nr.records['all']:
                print(f"IPv6 networks: {len(nr.records['all']['ip6'])}")

    Testing cache management::

        # Use custom cache file for testing
        nr = NetReader(cf, 'blacknets', cachefile='/tmp/test_cache.json')

    Note
    ----
    This class presents the same interface as ListReader for consistency
    in fwmanage.py. Both provide a `records` attribute for processing.

    See Also
    --------
    NetReaderFromFiles : Worker class that actually reads and processes files
    netprocess.NetProcess : Processes records into nftables commands

    """

    # Class-level templates (shared across instances)
    # Empty cache structure
    cache: dict[str, Any] = {'files': {},
                             'ip': [],
                             'ip6': []}

    # Template for output records
    recordstemplate: dict[str, dict[str, str]] = {
        'all': {'name': 'blacknets_set'}}

    # Instance-level output records
    records: dict[str, dict[str, Any]] = {}

    def __init__(self,
                 cf: Config,
                 listname: str,
                 cachefile: str | None = None) -> None:
        """Initialize NetReader and manage cache lifecycle.

        Loads network blacklist data either from JSON cache (if valid)
        or by reading *.nets files (if cache invalid or missing).

        Args:
            cf: Configuration instance
            listname: Name of list directory (typically 'blacknets')
            cachefile: Optional custom cache file path for testing.
                      If None, uses cf.varfilepath('blacknets_cache')

        Returns:
            None. Sets self.cache and self.records as side effects.

        Note:
            Called from fwmanage.py with same interface as ListReader.
            If blacknets.d directory doesn't exist or contains no *.nets
            files, the method returns early with empty records.

        Example:
            Standard usage from fwmanage.py::

                nr = NetReader(cf, 'blacknets')
                # records populated if files exist

            Testing with custom cache file::

                nr = NetReader(cf, 'blacknets',
                              cachefile='/tmp/test_cache.json')

        """
        self.cf: Config = cf
        if cachefile is None:
            self.cachepath: Path = cf.varfilepath('blacknets_cache')
        else:
            self.cachepath = Path(cachefile)

        blacknets_d: Path = cf.etcpath(listname)

        # Safety check - if directory doesn't exist, return early
        if not blacknets_d.exists():
            return

        needcache: bool = True
        if self.cachepath.exists():
            self.cache = self.loadjson()
            needcache = False

        # Find all *.nets files in directory
        files: list[Path] = [f for f in blacknets_d.glob('*.nets')
                             if f.is_file()]

        # If no files, remove cache if it exists and return
        if not any(files):
            # will be False if cache file is not found
            if not needcache:
                self.cachepath.unlink()
            return

        # Rebuild cache if needed
        if needcache \
           or self.cf.force_full_install \
           or self.check_on_cache(blacknets_d, files):

            # Load data from files
            nrf: NetReaderFromFiles = NetReaderFromFiles(cf, listname,
                                                         files=files)
            for ix in ('ip', 'ip6'):
                self.cache[ix] = nrf.lists[ix]

            # Update file name cache with current mtimes
            newfiles: dict[str, int] = {}
            for file in files:
                newfiles[file.name] = int(file.stat().st_mtime)
            self.cache['files'] = newfiles

            # Save the cache file
            self.savejson(self.cache)

        # Build output records from cache
        newrecord: dict[str, dict[str, Any]] = dict(self.recordstemplate)
        if any(self.cache['ip']):
            newrecord['all']['ip'] = self.cache['ip']
        if any(self.cache['ip6']):
            newrecord['all']['ip6'] = self.cache['ip6']
        # Only set records if we have at least one IP list
        if 'ip' in newrecord['all'] or 'ip6' in newrecord['all']:
            self.records = newrecord

    def check_on_cache(self,
                       blacknets_d: Path,
                       files: list[Path]) -> bool:
        """Check if cache needs reloading due to file changes.

        Compares current *.nets files with cached file list and mtimes
        to determine if cache is stale.

        Args:
            blacknets_d: Path to blacknets.d directory
            files: List of Path objects for current *.nets files

        Returns:
            True if cache needs reloading (file added/deleted/modified)
            False if cache is still valid

        Note:
            This method implements the cache invalidation logic:
            1. Check if any cached files were deleted
            2. Check if any new files appeared
            3. Check if any existing files have newer mtimes

        Example:
            Internal use only (called from __init__)::

                if self.check_on_cache(blacknets_d, files):
                    # Rebuild cache from files
                    nrf = NetReaderFromFiles(cf, listname, files=files)

        """
        # Shorthand for cached file list
        cfiles: dict[str, int] = self.cache['files']

        # First check if a file has been deleted since we were last here
        for storedname in cfiles:
            storedpath: Path = blacknets_d / storedname
            if storedpath not in files:
                return True

        # Now scan current files for new or modified files
        for file in files:
            # New file?
            filename: str = file.name
            if filename not in cfiles:
                return True

            # File changed (mtime newer)?
            mtime: int = int(file.stat().st_mtime)
            if mtime > cfiles[filename]:
                return True

        return False

    def loadjson(self) -> dict[str, Any]:
        """Load cache data from JSON file.

        Returns:
            Dictionary with cache structure:
            {'files': {}, 'ip': [], 'ip6': []}

        Note:
            If JSON is malformed, an exception will be raised.
            The caller (usually __init__) should handle this.

        Example:
            Internal use only::

                if self.cachepath.exists():
                    self.cache = self.loadjson()

        """
        contents: str = self.cachepath.read_text()
        jobj: dict[str, Any] = json.loads(contents)
        return jobj

    def savejson(self, cache: dict[str, Any]) -> None:
        """Save cache data to JSON file.

        Args:
            cache: Cache dictionary to save

        Returns:
            None

        Note:
            File is written with default permissions. The cache file
            is typically stored in /var/lib/nftfw/ which should have
            restricted permissions.

        Example:
            Internal use only::

                self.cache['ip'] = processed_ipv4_list
                self.savejson(self.cache)

        """
        contents: str = json.dumps(cache)
        self.cachepath.write_text(contents)


class NetReaderFromFiles:
    """Worker class that reads and processes *.nets files.

    Reads all *.nets files from blacknets.d directory, validates network
    addresses, eliminates duplicates and overlaps, and produces clean
    lists of IPv4 and IPv6 networks.

    Processing Pipeline
    -------------------
    1. Read all *.nets files
    2. Parse each line (remove comments, validate syntax)
    3. Convert addresses to network objects
    4. Handle IPv6-mapped IPv4 addresses (::ffff:x.x.x.x)
    5. Store with footprint-based deduplication
    6. Eliminate overlapping networks (collapse_addresses)
    7. Convert back to strings, removing /32 and /128 suffixes

    Attributes
    ----------
    cf : Config
        Configuration instance
    commentre : re.Pattern[str]
        Compiled regex for removing comments (matches # and everything after)
    nets : dict[str, dict[int, IpAddressType]]
        Intermediate storage with footprint keys:
        - 'ip': {footprint: IPv4Network, ...}
        - 'ip6': {footprint: IPv6Network, ...}
    lists : dict[str, list[str]]
        Final output lists:
        - 'ip': ['192.0.2.0/24', '198.51.100.42', ...]
        - 'ip6': ['2001:db8::/32', ...]
    source : dict[str, list[int]]
        Tracks which file contains which address:
        - {filename: [footprint1, footprint2, ...]}

    Example
    -------
    Reading blacknets from files::

        from .config import Config
        from .netreader import NetReaderFromFiles

        cf = Config()
        nrf = NetReaderFromFiles(cf, 'blacknets')

        # Access processed lists
        print(f"IPv4 networks: {nrf.lists['ip']}")
        print(f"IPv6 networks: {nrf.lists['ip6']}")

    With explicit file list::

        from pathlib import Path
        files = [Path('/etc/nftfw/blacknets.d/country1.nets'),
                 Path('/etc/nftfw/blacknets.d/country2.nets')]
        nrf = NetReaderFromFiles(cf, 'blacknets', files=files)

    Note
    ----
    This class is typically used by NetReader, not called directly.
    It performs the heavy lifting of file parsing and network processing.

    See Also
    --------
    NetReader : Main class that uses this for cache rebuilds
    ipaddress.collapse_addresses : Used for overlap elimination

    """

    # Class-level storage (initialised for each instance)
    # Using dict for fast unique settings
    # Key is footprint (int), value is network object
    nets: dict[str, dict[int, IpAddressType]] = {'ip': {}, 'ip6': {}}

    # Final output lists (strings)
    lists: dict[str, list[str]] = {'ip': [], 'ip6': []}

    # Source file tracking
    # Key is filename, value is list of footprints from that file
    source: dict[str, list[int]] = {}

    def __init__(self,
                 cf: Config,
                 listname: str,
                 files: list[Path] | None = None) -> None:
        """Initialize and process all *.nets files.

        Reads all *.nets files from blacknets.d directory, processes
        each line, and populates self.lists with clean network strings.

        Args:
            cf: Configuration instance
            listname: Name of list directory (typically 'blacknets')
            files: Optional list of Path objects to process.
                  If None, scans blacknets.d for *.nets files

        Returns:
            None. Populates self.lists['ip'] and self.lists['ip6']

        Note:
            Processing includes:
            - Comment removal
            - IPv4/IPv6 detection and validation
            - IPv6-mapped IPv4 conversion
            - Duplicate elimination via footprints
            - Overlap removal via collapse_addresses
            - /32 and /128 suffix removal for single addresses

        Example:
            Typical usage from NetReader::

                nrf = NetReaderFromFiles(cf, 'blacknets', files=file_list)
                ipv4_nets = nrf.lists['ip']
                ipv6_nets = nrf.lists['ip6']

        """
        self.cf: Config = cf
        blacknets_d: Path = cf.etcpath(listname)
        # Regex to remove comments (everything after #)
        self.commentre: re.Pattern[str] = re.compile(r'^(.*?)#.*$')

        # Allow the class to be called with no file argument
        if files is None:
            files = [f for f in blacknets_d.glob('*.nets')
                     if f.is_file()]

        # Process all files
        if any(files):
            for file in files:
                lineno: int = 1
                contents: str = file.read_text()
                for line in contents.split('\n'):
                    self.line_process(line, file, lineno)
                    lineno += 1

            # Post-processing: remove overlaps, sort, convert to strings
            for ix in ('ip', 'ip6'):
                # Remove overlapping networks using ipaddress library
                nets: list[IpAddressType] = list(
                    self.delete_overlaps(self.nets[ix]))

                nets = sorted(nets)

                # Convert objects to strings
                # Remove /32 or /128 suffix from single addresses
                self.lists[ix] = [str(self.full_address(ipt))
                                  for ipt in nets]

    # pylint: disable=too-many-branches
    def line_process(self,
                     line: str,
                     filename: Path,
                     lineno: int) -> None:
        """Process a single line from a *.nets file.

        Handles comment removal, blank line skipping, address/network
        validation, and storage. Logs errors for invalid entries.

        Args:
            line: Line of text to process
            filename: Path object for source file (used in error messages)
            lineno: Line number (used in error messages)

        Returns:
            None. Updates self.nets and self.source as side effects.

        Note:
            Processing logic:
            1. Remove comments (# and everything after)
            2. Strip whitespace
            3. Skip blank lines
            4. If no / in line: treat as single IP address
            5. If / in line: treat as CIDR network
            6. For IPv6 networks: check for IPv4-mapped addresses
            7. Store with footprint-based deduplication

        Example:
            Internal use only (called from __init__)::

                for line in file_contents:
                    self.line_process(line, filepath, line_number)

        """
        # Remove comments and blank lines
        ma: re.Match[str] | None = self.commentre.search(line)
        if ma:
            line = ma.group(1)
        # Remove whitespace
        line = line.strip()
        if line == '':
            return

        # Process single IP addresses (no CIDR notation)
        if '/' not in line:
            try:
                ipt: ipaddress.IPv4Address | ipaddress.IPv6Address = (
                    ipaddress.ip_address(line))
                footp: int | None = self.store_addr(ipt)
                if footp is not None:
                    self.store_source(filename, footp)
            except ValueError as e:
                log.error('blacknets file %s, line %d: failed on %s - %s',
                          str(filename),
                          lineno,
                          line,
                          str(e))
            # All done for single addresses
            return

        # Process CIDR networks (from here on)
        try:
            ipt_net: ipaddress.IPv4Network | ipaddress.IPv6Network = (
                ipaddress.ip_network(line, strict=False))
        except ValueError as e:
            log.error('blacknets file %s, line %d: failed on %s - %s',
                      str(filename),
                      lineno,
                      line,
                      str(e))
            return

        # IPv4 networks are ready to store
        if isinstance(ipt_net, ipaddress.IPv4Network):
            footp = self.store_net(ipt_net)
            if footp is not None:
                self.store_source(filename, footp)
            return

        # IPv6 networks: check for IPv4-mapped addresses (::ffff:x.x.x.x)
        ipcheck: ipaddress.IPv4Network | None | str = (
            self.convert_to_ipv4(ipt_net))
        if ipcheck is None:
            # Pure IPv6 network
            footp = self.store_net(ipt_net)
            if footp is not None:
                self.store_source(filename, footp)
        elif ipcheck == 'error':
            # Conversion failed
            log.error('blacknets file %s, line %d: '
                     'could not convert ipv6 to ipv4 - %s',
                      str(filename),
                      lineno,
                      str(ipt_net))
        else:
            # Successfully converted to IPv4
            # After checking for None and 'error', ipcheck must be IPv4Network
            footp = self.store_net(cast(ipaddress.IPv4Network, ipcheck))
            if footp is not None:
                self.store_source(filename, footp)

    @staticmethod
    def convert_to_ipv4(ipt: ipaddress.IPv6Address |
                        ipaddress.IPv6Network
                        ) -> ipaddress.IPv4Network | None | str:
        """Convert IPv6-mapped IPv4 address to native IPv4.

        Detects IPv6 addresses that are really IPv4 addresses using the
        official IPv6 representation (::ffff:x.x.x.x) and converts them
        to native IPv4 networks with correct prefix length.

        Args:
            ipt: IPv6 address or network object

        Returns:
            IPv4Network if conversion successful
            None if no conversion needed (pure IPv6)
            'error' string if conversion failed

        Note:
            Prefix length conversion for networks:
            IPv6 /N maps to IPv4 /(N-96) since ::ffff: is 96 bits.
            For example: ::ffff:192.0.2.0/120 → 192.0.2.0/24

        Example:
            Convert IPv6-mapped IPv4 address::

                import ipaddress
                from .netreader import NetReaderFromFiles

                # IPv6-mapped address
                ip6 = ipaddress.ip_address('::ffff:192.0.2.1')
                result = NetReaderFromFiles.convert_to_ipv4(ip6)
                # result: IPv4Network('192.0.2.1/32')

            Convert IPv6-mapped network::

                net6 = ipaddress.ip_network('::ffff:192.0.2.0/120')
                result = NetReaderFromFiles.convert_to_ipv4(net6)
                # result: IPv4Network('192.0.2.0/24')

            Pure IPv6 (no conversion)::

                net6 = ipaddress.ip_network('2001:db8::/32')
                result = NetReaderFromFiles.convert_to_ipv4(net6)
                # result: None

        """
        is_net: bool = False
        ipcheck: ipaddress.IPv6Address
        if isinstance(ipt, ipaddress.IPv6Network):
            is_net = True
            ipcheck = ipt.network_address
        else:
            ipcheck = ipt

        # Get IPv4-mapped representation
        # ipcheck is either the original IP address
        # or (for networks) the network_address
        ipmapped: ipaddress.IPv4Address | None = ipcheck.ipv4_mapped
        # If ipmapped is None, it's a pure IPv6 address/network
        if ipmapped is None:
            return None

        # Construct new IPv4 address/network
        # Start with the IPv4 address as string
        newip: str = str(ipmapped)

        # For single addresses (not networks), make /32
        if not is_net:
            newip += '/32'
        else:
            # For networks, calculate IPv4 prefix from IPv6 prefix
            # ::ffff: is 96 bits, so subtract 96 from IPv6 prefix
            newpre: int = 32 - (128 - ipt.prefixlen)  # type: ignore
            if 0 < newpre <= 32:
                newip += '/' + str(newpre)
            else:
                return 'error'

        # Create IPv4 network object
        try:
            outip: ipaddress.IPv4Network = cast(ipaddress.IPv4Network,
                                                 ipaddress.ip_network(newip,
                                                                      strict=False))
        except ValueError:
            return 'error'
        return outip

    def store_net(self,
                  ipt: ipaddress.IPv4Network | ipaddress.IPv6Network
                  ) -> int | None:
        """Store network address with deduplication.

        Uses footprint-based storage to prevent duplicates. Filters out
        erroneous full-range networks (0.0.0.0/32, 255.255.255.255/32,
        ::/128, ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128).

        Args:
            ipt: IPv4 or IPv6 network object

        Returns:
            Footprint key (int) if stored successfully
            None if network was filtered out

        Note:
            Uses ipt.version to determine protocol (4 or 6).
            Generates unique footprint key via get_footprint().
            Stores in self.nets['ip'] or self.nets['ip6'].

        Example:
            Internal use only::

                import ipaddress
                net = ipaddress.ip_network('192.0.2.0/24')
                footprint = self.store_net(net)
                # footprint: unique int key
                # self.nets['ip'][footprint] = net

        """
        if ipt.version == 4:
            ix: str = 'ip'
            mask: int = 0xff
        else:
            ix = 'ip6'
            mask = 0xffff

        # Filter out erroneous full-range addresses
        # These are errors in the source lists
        if ipt.prefixlen == ipt.max_prefixlen:
            possiblenet: int = int(ipt.network_address) & mask
            if possiblenet in (0, mask):
                return None

        # Prevent duplicates using footprint as dict key
        footp: int = self.get_footprint(ipt)
        self.nets[ix][footp] = ipt
        return footp

    def store_addr(self,
                   ipt: ipaddress.IPv4Address | ipaddress.IPv6Address
                   ) -> int | None:
        """Store single IP address as a network (/32 or /128).

        Converts single IP addresses to network objects with full prefix
        length (/32 for IPv4, /128 for IPv6) and delegates to store_net().

        Args:
            ipt: IPv4 or IPv6 address object

        Returns:
            Footprint key (int) if stored successfully
            None if address was filtered out

        Note:
            Single addresses from *.nets files are converted to /32 or /128
            networks for uniform processing. The full_address() method will
            later convert them back to addresses when outputting strings.

        Example:
            Internal use only::

                import ipaddress
                addr = ipaddress.ip_address('192.0.2.42')
                footprint = self.store_addr(addr)
                # Stored as IPv4Network('192.0.2.42/32')

        """
        # Convert address to network with full prefix
        prelen: str = "/32" if ipt.version == 4 else "/128"
        newip: ipaddress.IPv4Network | ipaddress.IPv6Network = (
            ipaddress.ip_network(str(ipt) + prelen, strict=False))
        return self.store_net(newip)

    def store_source(self, filename: Path, footp: int) -> None:
        """Store source file information for debugging.

        Tracks which *.nets file contains which network addresses
        using footprint keys.

        Args:
            filename: Path object for source file
            footp: Footprint key for the network

        Returns:
            None. Updates self.source dict.

        Note:
            This tracking is useful for debugging to determine where
            a particular network was defined. Not currently used in
            production but kept for future diagnostics.

        Example:
            Internal use only::

                self.store_source(Path('country.nets'), 12345)
                # self.source['country.nets'] = [12345, ...]

        """
        fname: str = filename.name
        if fname not in self.source:
            self.source[fname] = []
        self.source[fname].append(footp)

    @staticmethod
    def get_footprint(ipt: ipaddress.IPv4Network |
                      ipaddress.IPv6Network) -> int:
        """Generate unique integer key for network address.

        Creates a unique footprint by combining the network address
        and prefix length into a single integer. Used as dict key
        for deduplication.

        Args:
            ipt: IPv4 or IPv6 network object

        Returns:
            Footprint as integer: (network_address << 8) | prefix_length

        Note:
            Formula: footprint = (network_address_as_int << 8) | prefix_len
            This ensures different networks have different footprints even
            if they have the same network address but different prefixes.

        Example:
            Generate footprint for IPv4 network::

                import ipaddress
                from .netreader import NetReaderFromFiles

                net = ipaddress.ip_network('192.0.2.0/24')
                fp = NetReaderFromFiles.get_footprint(net)
                # fp: (3221225984 << 8) | 24

            Different prefixes create different footprints::

                net1 = ipaddress.ip_network('192.0.2.0/24')
                net2 = ipaddress.ip_network('192.0.2.0/25')
                fp1 = NetReaderFromFiles.get_footprint(net1)
                fp2 = NetReaderFromFiles.get_footprint(net2)
                # fp1 != fp2

        """
        working: ipaddress.IPv4Address | ipaddress.IPv6Address = (
            ipt.network_address)
        cidr: int = ipt.prefixlen
        footprint: int = (int(working) << 8) | cidr
        return footprint

    @staticmethod
    def delete_overlaps(srcdict: dict[int, IpAddressType]
                       ) -> list[IpAddressType]:
        """Remove overlapping network entries using collapse_addresses.

        Uses ipaddress.collapse_addresses() to eliminate overlapping
        and adjacent networks, producing the minimal set of networks
        that covers all addresses.

        Args:
            srcdict: Dictionary of footprint → network object

        Returns:
            Generator yielding non-overlapping network objects

        Note:
            This uses the standard library's collapse_addresses() which:
            - Removes networks completely contained in larger networks
            - Merges adjacent networks where possible
            - Returns minimal covering set

        Example:
            Eliminate overlapping networks::

                import ipaddress
                from .netreader import NetReaderFromFiles

                nets = {
                    1: ipaddress.ip_network('192.0.2.0/24'),
                    2: ipaddress.ip_network('192.0.2.0/25'),  # overlap
                    3: ipaddress.ip_network('198.51.100.0/24')
                }
                result = list(NetReaderFromFiles.delete_overlaps(nets))
                # result: [IPv4Network('192.0.2.0/24'),
                #          IPv4Network('198.51.100.0/24')]

        """
        # collapse_addresses requires homogeneous types (all IPv4 or all IPv6)
        # In practice, srcdict contains only networks of same protocol family
        return list(ipaddress.collapse_addresses(srcdict.values()))  # type: ignore[type-var]

    @staticmethod
    def full_address(ipt: ipaddress.IPv4Network |
                     ipaddress.IPv6Network |
                     ipaddress.IPv4Address |
                     ipaddress.IPv6Address
                     ) -> (ipaddress.IPv4Network | ipaddress.IPv6Network |
                           ipaddress.IPv4Address | ipaddress.IPv6Address):
        """Convert full-prefix networks to addresses.

        Networks with full prefix length (/32 for IPv4, /128 for IPv6)
        are converted to address objects by returning their network_address.
        Other networks are returned unchanged.

        Args:
            ipt: IPv4 or IPv6 network or address object

        Returns:
            Address object if network has full prefix (/32 or /128)
            Network object otherwise (unchanged)

        Note:
            This is used during string conversion to produce cleaner
            output. Instead of "192.0.2.42/32", we output "192.0.2.42".

        Example:
            Convert /32 network to address::

                import ipaddress
                from .netreader import NetReaderFromFiles

                net = ipaddress.ip_network('192.0.2.42/32')
                result = NetReaderFromFiles.full_address(net)
                # result: IPv4Address('192.0.2.42')
                # str(result): '192.0.2.42'

            Keep normal networks unchanged::

                net = ipaddress.ip_network('192.0.2.0/24')
                result = NetReaderFromFiles.full_address(net)
                # result: IPv4Network('192.0.2.0/24')
                # str(result): '192.0.2.0/24'

        """
        if ipt.prefixlen == ipt.max_prefixlen:  # type: ignore
            return ipt.network_address  # type: ignore
        return ipt
