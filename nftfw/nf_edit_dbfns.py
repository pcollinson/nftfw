"""Database functions for nftfwedit - Add, delete, and blacklist operations.

This module provides the DbFns class which implements database operations
for the nftfwedit utility. It handles adding IP addresses to the database,
creating blacklist files, and deleting entries while maintaining consistency
between the database and filesystem.

**Operations:**

add
    Add IP addresses to the database with pattern and port information.
    Updates match counts and incidents without creating blacklist files.

blacklist
    Add IP addresses to both database and blacklist directory as .auto files.
    Creates files and optionally sets minimum match count thresholds.

delete
    Remove IP addresses from database and delete associated blacklist files.

remove
    Delete blacklist files only, leaving database entries intact.

**Integration:**

The DbFns class integrates with the Scheduler to provide proper locking
and is called via the execute() method which dispatches to the appropriate
operation based on command-line arguments.

**Workflow:**

1. Validate IP addresses using NormaliseAddress
2. Check database for existing entries
3. Perform requested operation (add/blacklist/delete/remove)
4. Update database and/or filesystem as needed
5. Return count of files affected

**Related Modules:**
    - nftfwedit: Main database editor utility that uses this module
    - fwdb: Database access layer
    - blacklist: Blacklist file creation and management
    - normaliseaddress: IP address validation and normalisation
    - scheduler: Provides locking for concurrent access

Example:
    Add IP addresses to database::

        from nftfw.config import Config
        from nftfw.nf_edit_dbfns import DbFns

        cf = Config()
        cf.editargs = {
            'cmd': 'add',
            'iplist': ['192.168.1.100', '10.0.0.50'],
            'port': '22',
            'pattern': 'sshd',
            'matches': 5
        }

        dbfns = DbFns(cf)
        result = dbfns.execute()

    Blacklist IP addresses::

        cf.editargs = {
            'cmd': 'blacklist',
            'iplist': ['192.168.1.100'],
            'port': None,  # Use existing from database
            'pattern': None,  # Use existing from database
            'matches': 10
        }

        result = dbfns.execute()
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .normaliseaddress import NormaliseAddress
from .fwdb import FwDb
from .blacklist import BlackList

if TYPE_CHECKING:
    from .config import Config

log = logging.getLogger('nftfw')

class DbFns:
    """Database operations for IP address management in nftfwedit.

    This class provides methods for adding, deleting, and blacklisting IP
    addresses. It maintains consistency between the database and blacklist
    directory, validates IP addresses, and integrates with the Scheduler
    for proper locking.

    **Attributes:**
        cf: Config instance
        port: Port specification (str or None)
        pattern: Pattern name (str or None)
        matches: Match count (int or None)

    **Operations:**

    add()
        Add IP addresses to database without creating blacklist files

    blacklist()
        Add IP addresses to database and create blacklist files

    delete()
        Remove IP addresses from database and delete blacklist files

    remove()
        Delete blacklist files only, preserving database entries

    **Scheduler Integration:**

    The execute() method serves as the entry point for the Scheduler,
    dispatching to the appropriate operation based on cf.editargs['cmd'].

    Example:
        Via scheduler::

            cf = Config()
            cf.editargs = {'cmd': 'add', 'iplist': [...], ...}
            dbfns = DbFns(cf)
            files_changed = dbfns.execute()

        Direct method call::

            dbfns = DbFns(cf)
            dbfns.port = '22'
            dbfns.pattern = 'sshd'
            dbfns.matches = 5
            dbfns.add(['192.168.1.100'])
    """

    cf: Config
    port: str | None
    pattern: str | None
    matches: int | None

    def __init__(self, cf: Config) -> None:
        """Initialise DbFns with configuration.

        Sets up the instance with configuration and initialises operation
        parameters (port, pattern, matches) to None. These are set by
        execute() or directly before calling operation methods.

        Args:
            cf: Config instance with paths and settings

        Returns:
            None

        Example:
            Standard initialization::

                from nftfw.config import Config

                cf = Config()
                dbfns = DbFns(cf)
        """
        self.cf = cf
        self.port = None
        self.pattern = None
        self.matches = None

    def execute(self) -> int:
        """Scheduler access point for database operations.

        This method is called by the Scheduler to execute database operations.
        It retrieves command and parameters from cf.editargs, dispatches to
        the appropriate method, and returns the number of files changed.

        **Parameters from cf.editargs:**

        cmd (str)
            Command to execute: 'add', 'blacklist', 'delete', or 'remove'

        iplist (list[str])
            List of IP addresses to process

        port (str | None)
            Comma-separated port list or None to use existing

        pattern (str | None)
            Pattern name or None to use existing

        matches (int)
            Match count for database entries

        **Return Values:**

        - Returns 0 for 'add' command (no files created)
        - Returns count of files changed for other commands

        Args:
            None. Parameters retrieved from self.cf.editargs

        Returns:
            Number of files changed (0 for 'add' command)

        Example:
            Via scheduler::

                cf = Config()
                cf.editargs = {
                    'cmd': 'blacklist',
                    'iplist': ['192.168.1.100'],
                    'port': '22',
                    'pattern': 'sshd',
                    'matches': 10
                }

                dbfns = DbFns(cf)
                files_created = dbfns.execute()
                print(f"Created {files_created} blacklist files")
        """
        # name of function
        cmd: str = self.cf.editargs['cmd']
        fn = getattr(self, cmd)
        self.port = self.cf.editargs['port']
        self.pattern = self.cf.editargs['pattern']
        self.matches = self.cf.editargs['matches']
        files: int = fn(self.cf.editargs['iplist'])
        if cmd == 'add':
            return 0
        return files


    def add(self, iplist: list[str]) -> int:
        """Add IP addresses to database without creating blacklist files.

        Adds IP addresses to the database with the specified port and pattern.
        This is a wrapper around blacklist() with create_files=False, which
        prevents creation of blacklist directory files.

        **Requirements:**

        - self.port must be set (comma-separated port list)
        - self.pattern must be set (pattern name)
        - self.matches must be set (match count)

        **Behaviour:**

        - Validates IP addresses using NormaliseAddress
        - Adds new IPs to database or updates existing ones
        - Does NOT create files in blacklist directory
        - Does NOT set minimum match count thresholds

        Args:
            iplist: List of IP address strings to add

        Returns:
            Number of files added (always 0 since no files are created)

        Example:
            Add IPs to database only::

                dbfns = DbFns(cf)
                dbfns.port = '22,80'
                dbfns.pattern = 'sshd'
                dbfns.matches = 5

                result = dbfns.add(['192.168.1.100', '10.0.0.50'])
                # Database updated, no files created
        """
        return self.blacklist(iplist,
                              create_files=False,
                              set_min_matches=False)

    def blacklist(self, iplist: list[str], create_files: bool = True,
                  set_min_matches: bool = True) -> int:
        """Add IP addresses to database and optionally create blacklist files.

        This is the main workhorse method that handles both adding IPs to the
        database and creating blacklist files. It integrates with BlackList
        class for file creation and maintains consistency between database
        and filesystem.

        **Parameters:**

        create_files
            If True, create .auto files in blacklist directory (default: True)
            If False, only update database (used by add() method)

        set_min_matches
            If True, enforce minimum match count from block_after config
            If False, use exact match count provided (used by add() method)

        **Workflow:**

        1. Validate all IP addresses
        2. Check which IPs exist in database
        3. For new IPs, verify port and pattern are provided
        4. For existing IPs, use database values if port/pattern not provided
        5. Build work dictionary with all IPs and their settings
        6. Apply minimum match count threshold for new IPs (if enabled)
        7. Call BlackList.install_ips() to update database and create files
        8. Return count of files created

        **Match Count Handling:**

        For new IPs with set_min_matches=True:
            - If provided matches < block_after, set to block_after
            - This ensures new IPs meet threshold for blacklisting

        For existing IPs or set_min_matches=False:
            - Use exact match count provided

        Args:
            iplist: List of IP address strings to process
            create_files: Whether to create blacklist directory files
            set_min_matches: Whether to enforce minimum match count threshold

        Returns:
            Number of files created in blacklist directory

        Example:
            Blacklist with file creation::

                dbfns = DbFns(cf)
                dbfns.port = '22'
                dbfns.pattern = 'sshd'
                dbfns.matches = 10

                files = dbfns.blacklist(['192.168.1.100'])
                # Creates database entry and .auto file

            Update existing entry::

                dbfns.port = None  # Use existing from database
                dbfns.pattern = None  # Use existing from database
                dbfns.matches = 15  # Increment match count

                files = dbfns.blacklist(['192.168.1.100'])
                # Updates database, recreates file with new count
        """
        # pylint: disable=too-many-locals, too-many-branches

        iplist = self.ensure_legal_addresses(iplist, 'nftfwedit blacklist')
        if iplist is None:
            return 0

        fwdb: FwDb = FwDb(self.cf)

        bl: BlackList = BlackList(self.cf)
        bl.report_whitelisting = True
        # Inhibit file creation if wanted
        if not create_files:
            bl.file_create = False

        # Generate database entries for update
        # use work to retain database values
        # check if we need ports and patterns
        toadd: list[str] = []
        current: dict[str, dict[str, Any]] = {}
        for ip in iplist:
            # check if the ip is in the database
            indb = fwdb.lookup_by_ip(ip)
            if any(indb):
                current[ip] = indb[0]
            else:
                toadd.append(ip)
        fwdb.close()

        # any ips need adding?
        if any(toadd):
            # we need port or pattern
            if self.port is None \
               or self.pattern is None:
                ipe: str = ", ".join(toadd)
                log.error('Pattern and port needed for %s', ipe)
                return 0

        work: dict[str, dict[str, Any]] = {}
        for ip in iplist:
            if ip in current:
                if self.port is None:
                    self.port = 'update'
                if self.pattern is None:
                    self.pattern = current[ip]['pattern']
            work[ip] = {
                'ports': self.port,
                'pattern': self.pattern,
                'incidents': 1
                }
            # set matchcount
            work[ip]['matchcount'] = self.matches
            min_count: int = bl.block_after
            if ip in toadd and set_min_matches:
                # for new entries start matchcount at the threshold
                if self.matches is not None and self.matches < min_count:
                    work[ip]['matchcount'] = min_count

        # do one call to install_ips to minimise whitelist checking
        added: int = 0
        filesinstalled: int
        filesinstalled, _ = bl.install_ips(work)
        if filesinstalled > 0:
            added += filesinstalled
        return added

    def delete(self, iplist: list[str], delete_from_db: bool = True) -> int:
        """Delete IP addresses from database and blacklist directory.

        Removes IP addresses from the database and deletes associated .auto
        files from the blacklist directory. Can optionally preserve database
        entries while deleting files (used by remove() method).

        **Workflow:**

        1. Validate all IP addresses
        2. For each IP:
           - Delete from database (if delete_from_db=True and IP exists)
           - Delete .auto file from blacklist directory (if file exists)
        3. Log summary of deletions
        4. Return count of files deleted

        **File Name Conversion:**

        CIDR notation is converted from / to | for filesystem:
            - "192.168.1.0/24" becomes "192.168.1.0|24.auto"

        Args:
            iplist: List of IP address strings to delete
            delete_from_db: If True, delete from database; if False, delete
                           files only (default: True)

        Returns:
            Number of files deleted from blacklist directory

        Example:
            Complete deletion::

                dbfns = DbFns(cf)
                files = dbfns.delete(['192.168.1.100', '10.0.0.50'])
                # Removes from database and deletes .auto files

            File-only deletion (database preserved)::

                files = dbfns.delete(['192.168.1.100'], delete_from_db=False)
                # Deletes .auto file but keeps database entry
        """
        iplist = self.ensure_legal_addresses(iplist, 'nftfwedit delete')
        if iplist is None:
            return 0

        blacklistpath: Path = self.cf.etcpath('blacklist')

        fwdb: FwDb = FwDb(self.cf)

        # do database update first
        ipsdeleted: int = 0
        filesdeleted: int = 0
        for ip in iplist:
            indb = fwdb.lookup_by_ip(ip)
            if delete_from_db and any(indb):
                fwdb.delete_ip(ip)
                ipsdeleted += 1

            # does file exists
            file: str = ip.replace('/', '|')
            file += '.auto'
            path: Path = blacklistpath / file
            if path.exists():
                path.unlink()
                filesdeleted += 1

        fwdb.close()

        if ipsdeleted + filesdeleted > 0:
            log.info('Deleted - ips: %d, files: %d',
                     ipsdeleted, filesdeleted)

        return filesdeleted

    def remove(self, iplist: list[str]) -> int:
        """Remove blacklist files while preserving database entries.

        Deletes .auto files from the blacklist directory but leaves the
        database entries intact. This is useful for temporarily deactivating
        blacklist entries without losing their history.

        This is a wrapper around delete() with delete_from_db=False.

        Args:
            iplist: List of IP address strings to remove

        Returns:
            Number of files deleted from blacklist directory

        Example:
            Remove files but keep database history::

                dbfns = DbFns(cf)
                files = dbfns.remove(['192.168.1.100'])
                # File deleted, database entry preserved
        """
        return self.delete(iplist, delete_from_db=False)

    @staticmethod
    def normalise_ip_list(normalise: NormaliseAddress,
                         iplist: list[str]) -> list[str]:
        """Normalise and validate a list of IP addresses.

        Uses NormaliseAddress.normal() to validate and normalise each IP
        address. Invalid addresses are silently filtered out.

        **Validation:**

        Each IP is passed through NormaliseAddress.normal() which:
            - Validates IPv4 and IPv6 addresses
            - Handles CIDR notation
            - Checks against whitelist (if configured)
            - Filters local addresses in production mode

        Args:
            normalise: Instance of NormaliseAddress configured for validation
            iplist: List of IP address strings to validate

        Returns:
            List of valid, normalised IP address strings.
            May be shorter than input if some IPs are invalid.

        Example:
            Validate IP list::

                normalise = NormaliseAddress(cf, "test")
                ips = ['192.168.1.100', 'invalid', '10.0.0.50']
                valid = DbFns.normalise_ip_list(normalise, ips)
                # Returns: ['192.168.1.100', '10.0.0.50']
        """
        added: list[str] = []
        for ip in iplist:
            newip: str | None = normalise.normal(ip)
            if newip is not None:
                added.append(newip)
        return added

    def ensure_legal_addresses(self, iplist: list[str],
                               fromwhere: str) -> list[str]:
        """Normalise IP addresses and log any invalid entries.

        Validates all IP addresses using NormaliseAddress and logs an error
        message if any addresses fail validation. This provides user feedback
        about which IPs were rejected.

        **Validation:**

        Uses normalise_ip_list() to validate each IP. Invalid addresses are:
            - Filtered out from the return list
            - Logged as an error with details

        Args:
            iplist: List of IP address strings to validate
            fromwhere: Context string for error messages (e.g., "nftfwedit add")

        Returns:
            List of valid, normalised IP address strings.
            May be shorter than input if some IPs failed validation.

        Example:
            Validate with error reporting::

                dbfns = DbFns(cf)
                ips = ['192.168.1.100', 'bad-ip', '10.0.0.50']
                valid = dbfns.ensure_legal_addresses(ips, 'nftfwedit add')
                # Returns: ['192.168.1.100', '10.0.0.50']
                # Logs: "Does not pass validation tests: bad-ip"
        """
        normalise: NormaliseAddress = NormaliseAddress(self.cf, fromwhere)
        normal_iplist: list[str] = self.normalise_ip_list(normalise, iplist)
        if len(normal_iplist) != len(iplist):
            deleted: list[str] = list(set(iplist) - set(normal_iplist))
            if any(deleted):
                log.error('Does not pass validation tests: %s',
                          ", ".join(deleted))
        return normal_iplist
