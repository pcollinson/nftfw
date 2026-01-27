"""Whitelist management system for nftfw.

This module provides automatic whitelist management by scanning system login
records (wtmp/utmp) and creating whitelist entries for successful logins from
global IP addresses. It also manages automatic expiry of old whitelist entries.

Architecture
------------
The WhiteList class scans the wtmp file (or utmp) for user logins and:
1. Identifies global IP addresses from successful logins
2. Creates .auto files in whitelist.d for new IPs
3. Converts IPv6 addresses to /112 networks (configurable)
4. Expires old .auto files based on configured retention period
5. Respects user-created whitelist entries (files without .auto extension)

Workflow
--------
1. **Check for disabled file**: Skip if whitelist.d/disabled exists
2. **Scan wtmp**: Read login records since last scan (tracked by lastutmp file)
3. **Filter global IPs**: Only whitelist globally routable addresses
4. **Install files**: Create .auto files in whitelist.d for new IPs
5. **Expire old entries**: Remove .auto files older than whitelist_expiry days

Configuration
-------------
From the [Whitelist] section of nftfw.ini:

- **wtmp_file** (str): Path to wtmp file, or 'utmp' for utmp file
  Default: system wtmp file (/var/log/wtmp)
- **whitelist_expiry** (int): Days before expiring .auto files
  Default: 8 days

Additional config from [Locations]:
- **default_ipv6_mask** (int): Network mask for IPv6 whitelist entries
  Default: 112 (creates /112 networks)

File Naming
-----------
- IP addresses: 192.0.2.1.auto
- IPv6 networks: 2001:db8::|64.auto (/ replaced with |)
- User files: No .auto extension (never auto-expired)

Example Usage
-------------
Basic whitelist scanning:

    from .config import Config
    from .whitelist import WhiteList

    cf = Config()
    wl = WhiteList(cf)
    changes = wl.whitelist()
    print(f"Whitelist changes: {changes}")

Scan wtmp for new entries only:

    ip4_list, ip6_list = wl.scan_wtmp()
    print(f"Found {len(ip4_list)} IPv4 and {len(ip6_list)} IPv6 addresses")

Manual file installation:

    changes = wl.fileinstall('192.0.2.1')

Expire old entries:

    expired = wl.expiry()
    print(f"Expired {expired} old entries")

See Also
--------
- whitelistcheck.py: Whitelist lookup for blacklist filtering
- fwmanage.py: Firewall management that loads whitelist files
- blacklist.py: Blacklist system that checks whitelist before blocking
"""
from __future__ import annotations

import time
from pathlib import Path
import ipaddress
import logging
from typing import TYPE_CHECKING, cast

from .nftfw_utmp import Utmp, UtmpDecode
from .utmpconst import *    # pylint: disable=unused-wildcard-import,wildcard-import

if TYPE_CHECKING:
    from .config import Config

log = logging.getLogger('nftfw')

class WhiteList:
    """Manages automatic whitelist entries based on system login records.

    This class implements the nftfw whitelist workflow:
    1. Scans wtmp (or utmp) for successful user logins since last scan
    2. Identifies IP addresses from login records
    3. Creates .auto files in whitelist.d for global IPs
    4. Converts IPv6 addresses to /112 networks (configurable)
    5. Expires old .auto files based on configured retention period

    The class tracks the last scan time using the mtime of the lastutmp file
    in the var directory (typically /var/lib/nftfw/lastutmp). Only login
    records newer than this timestamp are processed.

    Whitelist entries are created as .auto files in the whitelist.d directory.
    User-created whitelist files (without .auto extension) are never expired.

    A 'disabled' file in whitelist.d will prevent all whitelist operations.

    Attributes:
        cf (Config): Configuration instance
        wtmp_file (str): Path to wtmp file or special value 'utmp'
        whitelist_expiry (str): Days before expiring .auto files (as string from config)
        whitelistpath (Path): Path to whitelist.d directory

    Example:
        Basic usage scanning and expiring:

            cf = Config()
            wl = WhiteList(cf)
            changes = wl.whitelist()  # Scan and expire
            if changes:
                print(f"Made {changes} whitelist changes")

        Manual operations:

            # Scan wtmp only
            ipv4, ipv6 = wl.scan_wtmp()

            # Install specific IP
            wl.fileinstall('192.0.2.1')

            # Expire old entries only
            expired = wl.expiry()

    Note:
        IPv6 addresses are converted to networks using default_ipv6_mask
        (default /112) to whitelist entire customer networks rather than
        individual addresses, which is more practical given IPv6 address
        rotation in many environments.
    """

    def __init__(self, cf: Config) -> None:
        """Initialize WhiteList instance with configuration.

        Args:
            cf: Configuration instance

        Note:
            Loads configuration from [Whitelist] section and sets up paths.
            The wtmp_file can be a path, 'utmp' for the utmp file, or empty
            to use the system default wtmp file.
        """
        self.cf: Config = cf
        config = cf.get_ini_values_by_section('Whitelist')
        self.wtmp_file: str = cast(str, config['wtmp_file'])
        self.whitelist_expiry: str = cast(str, config['whitelist_expiry'])
        self.whitelistpath: Path = self.cf.etcpath('whitelist')

    def whitelist(self) -> int:
        """Execute complete whitelist workflow: scan wtmp and expire old entries.

        This is the main entry point for the whitelist action. It performs:
        1. Check for disabled file (whitelist.d/disabled)
        2. Scan wtmp for new logins (scan_wtmp)
        3. Filter for global IP addresses (is_global check)
        4. Create .auto files for new IPs (fileinstall)
        5. Convert IPv6 to networks using default_ipv6_mask
        6. Expire old .auto files (expiry)

        Returns:
            Number of changes made (files created + files expired)

        Example:
            Typical usage in nftfw workflow:

                wl = WhiteList(cf)
                changes = wl.whitelist()
                if changes:
                    # Trigger firewall reload
                    scheduler.enqueue('load')

        Note:
            Private/non-global IP addresses are silently skipped. Only globally
            routable addresses are whitelisted. For IPv6, the entire /112
            network is whitelisted (configurable via default_ipv6_mask).

            If whitelist.d/disabled exists, this method returns 0 immediately
            without performing any operations.
        """
        # symbiosis allows a file called disabled
        # in the whitelist directory to stop things happening
        disabled = self.whitelistpath / 'disabled'
        if disabled.exists():
            return 0

        # count number of changes
        changes = 0

        log.info('whitelist scan start')
        # look for work
        ip, ip6 = self.scan_wtmp()
        if any(ip+ip6):
            # scan ip's to be added
            # only add global ips
            for i in ip:
                if ipaddress.IPv4Address(i).is_global:
                    changes += self.fileinstall(i)

            for i in ip6:
                # need to make this into a /112 network
                # controlled by cf.default_ipv6_mask
                i6_addr = ipaddress.IPv6Address(i)
                if i6_addr.is_global:
                    msk = self.cf.default_ipv6_mask
                    i6_net = ipaddress.IPv6Network((i6_addr, msk), strict=False)
                    changes += self.fileinstall(str(i6_net))

        # expiry old entries
        log.info('whitelist expiry check')
        changes += self.expiry()
        log.info('whitelist scan end - changes: %s', changes)
        return changes

    def scan_wtmp(self) -> tuple[list[str], list[str]]:
        """Scan wtmp file for successful user logins and extract IP addresses.

        This method reads the wtmp file (or utmp) and extracts IP addresses from
        USER_PROCESS entries (successful logins). It only processes entries newer
        than the last scan time, which is tracked by the mtime of the lastutmp
        file in the var directory.

        Returns:
            Tuple of (ipv4_list, ipv6_list) where:
                - ipv4_list: List of IPv4 address strings
                - ipv6_list: List of IPv6 address strings

        Example:
            Scan for new logins:

                ipv4, ipv6 = wl.scan_wtmp()
                print(f"Found {len(ipv4)} IPv4 and {len(ipv6)} IPv6 logins")

            Result format:

                (['192.0.2.1', '198.51.100.42'], ['2001:db8::1'])

        Note:
            The wtmp file path is determined by:
            1. If wtmp_file config is 'utmp', use system utmp file
            2. If wtmp_file is a custom path, use that path
            3. Otherwise, use system default wtmp file (WTMP_FILE constant)

            The lastutmp file is touched after scanning to update the timestamp
            for the next scan. If lastutmp doesn't exist, all records are processed.

            If a custom wtmp file is specified but doesn't exist, logs an error
            and returns empty lists.
        """
        ip = []
        ip6 = []
        scanstart = 0
        scantime = self.cf.varfilepath('lastutmp')
        if scantime.exists():
            st = scantime.stat()
            scanstart = int(st.st_mtime)

        ufile = WTMP_FILE
        if self.wtmp_file is not None \
          and self.wtmp_file != "":
            if self.wtmp_file == 'utmp':
                ufile = UTMP_FILE
            else:
                ufile = self.wtmp_file
                if not Path(ufile).exists():
                    log.error('User specified wtmp file %s not found', ufile)
                    return [], []

        utmp = Utmp()
        utmp.utmpname(ufile)
        utmp.setutent()
        for utf in utmp.getutentbytype(USER_PROCESS):
            if utf.ut_tv.tv_sec < scanstart:
                continue
            ut = UtmpDecode(utf)
            if ut.ut_addr is not None:
                if ut.ut_addr_v4 is not None:
                    ip.append(ut.ut_addr_v4)
                elif ut.ut_addr_v6 is not None:
                    ip6.append(ut.ut_addr_v6)
        utmp.endutent()

        # update the time file
        scantime.touch()
        return ip, ip6

    def fileinstall(self, ip: str) -> int:
        """Install or update a whitelist file for an IP address.

        Creates a .auto file in the whitelist.d directory for the given IP
        address. If the file already exists, updates its mtime. If a user-created
        file (without .auto extension) exists for this IP, does nothing.

        Args:
            ip: IP address or network in string format (e.g., '192.0.2.1' or
                '2001:db8::/112'). Networks use | instead of / in filenames.

        Returns:
            1 if a file was created or touched, 0 if nothing was done

        Example:
            Install whitelist entries:

                # IPv4 address
                wl.fileinstall('192.0.2.1')  # Creates 192.0.2.1.auto

                # IPv6 network
                wl.fileinstall('2001:db8::/112')  # Creates 2001:db8::|112.auto

                # Already exists with user file
                Path('whitelist.d/192.0.2.1').touch()  # User file
                wl.fileinstall('192.0.2.1')  # Returns 0, no action

        Note:
            The / character in CIDR notation is replaced with | for filenames
            since / is not allowed in filenames. For example, 2001:db8::/112
            becomes 2001:db8::|112.auto.

            User-created whitelist files (without .auto extension) take precedence
            and prevent automatic file creation. This allows administrators to
            manually whitelist IPs without automatic expiry.

            Files are created with ownership set according to cf.chownpath().
        """
        # change any / to |
        if '/' in ip:
            ip = ip.replace('/', '|')

        # if we have a file matching the address
        # then we do nothing, it's been user installed
        userfile = self.whitelistpath / ip
        if userfile.exists():
            return 0
        # now we make one ending in .auto
        # or we just update the mtime on
        # an existing one
        fname = ip + '.auto'
        userfile = self.whitelistpath / fname
        userfile.touch()
        self.cf.chownpath(userfile)

        log.info('Whitelist created %s', userfile)
        return 1

    def expiry(self) -> int:
        """Expire old automatically-created whitelist entries.

        Removes .auto files from the whitelist.d directory that are older than
        the configured whitelist_expiry period (default 8 days). Only .auto files
        are expired; user-created files (without .auto extension) are never removed.

        Returns:
            Number of files expired and removed

        Example:
            Expire old entries:

                expired = wl.expiry()
                print(f"Removed {expired} expired whitelist entries")

            With custom expiry period in config:

                # nftfw.ini
                [Whitelist]
                whitelist_expiry = 14  # Keep for 14 days

                wl = WhiteList(cf)
                wl.expiry()  # Removes .auto files older than 14 days

        Note:
            The expiry threshold is based on file mtime (modification time).
            Files are expired when:
                current_time - file_mtime > whitelist_expiry * 86400 seconds

            Only files matching the pattern [0-9a-z]*.auto are considered for
            expiry. This includes:
            - IPv4 addresses: 192.0.2.1.auto
            - IPv6 networks: 2001:db8::|112.auto (using | instead of /)

            User-created files without the .auto extension are never expired,
            allowing permanent whitelist entries to be created manually.
        """
        changed = 0
        threshold = int(time.time()) - int(self.whitelist_expiry)*86400
        for p in self.whitelistpath.glob('[0-9a-z]*.auto'):
            stat = p.stat()
            if int(stat.st_mtime) < threshold:
                p.unlink()
                log.info('Whitelist expired %s', p)
                changed += 1
        return changed
