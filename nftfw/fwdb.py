"""Firewall database management for IP blacklisting.

This module provides the FwDb class, which manages the SQLite database storing
IP addresses that have been identified for blacklisting. It inherits from SqDb
and provides specialized methods for managing firewall-related IP data including
match counts, timestamps, ports, and pattern tracking.

The database schema differs from the original Symbiosis firewall and is not
compatible with it.

Key Features
------------
- IP-based lookup and management with unique constraint
- Pattern tracking for multiple detection patterns per IP
- Incident and match count tracking for threshold-based banning
- Port aggregation for multi-service blocking
- Timestamp tracking (first/last seen) for expiration
- DNSBL integration support (currently unused)
- Complex deletion queries with multiple criteria

Database Schema
---------------
The 'blacklist' table contains the following columns:

ip : str
    IP address that matched detection rules (primary key, unique)
pattern : str
    Comma-separated list of pattern names that matched this IP
incidents : int
    Number of distinct incidents for this IP (bumped by feedback scans)
matchcount : int
    Total number of log matches found (used for banning threshold)
first : int
    Unix timestamp of first incident
last : int
    Unix timestamp of last incident
ports : str
    Comma-separated list of ports matched (extended when patterns differ)
useall : int (boolean)
    If true (1), use all ports in firewall rules instead of specific ports
multiple : int (boolean)
    Reserved for future use (currently unused)
isdnsbl : int (boolean)
    If true (1), this IP was found in a DNS blacklist database (currently unused)

Usage Example
-------------
    from .config import Config
    from .fwdb import FwDb

    # Initialize configuration and database
    cf = Config()
    db = FwDb(cf)

    # Lookup an IP address
    results = db.lookup_by_ip('192.0.2.1')
    if results:
        print(f"IP found: {results[0]['incidents']} incidents")

    # Insert new IP record
    db.insert_ip({
        'ip': '192.0.2.100',
        'pattern': 'ssh-brute',
        'incidents': 1,
        'matchcount': 5,
        'first': 1699564800,
        'last': 1699564800,
        'ports': '22',
        'useall': 0,
        'multiple': 0,
        'isdnsbl': 0
    })

    # Update existing IP
    db.update_ip({'incidents': 2, 'matchcount': 10}, '192.0.2.100')

    # Clean old entries (last seen before timestamp)
    deleted = db.clean(lasttime=1699564800, incidents=1, matchcount=5)
    print(f"Cleaned {deleted} old entries")

See Also
--------
sqdb.SqDb : Base class providing SQLite database wrapper
blacklist : Module that uses FwDb for blacklist management
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any
import logging
from .sqdb import SqDb

if TYPE_CHECKING:
    from .config import Config

log = logging.getLogger('nftfw')


class FwDb(SqDb):
    """Manages the firewall IP blacklist database.

    This class provides specialized methods for managing IP addresses in the
    blacklist database. It inherits from SqDb and adds firewall-specific
    operations like IP lookup, deletion with complex criteria, and cleaning
    based on age and match thresholds.

    The database tracks not just IP addresses, but also metadata like:
    - Which patterns matched the IP
    - How many times it was seen (incidents and matchcount)
    - When it was first and last seen (for expiration)
    - Which ports were involved
    - Whether to block all ports or just specific ones

    Attributes:
        cf: Config instance for accessing configuration
        dbfile: Path to the SQLite database file
        conn: SQLite connection with Row factory enabled

    Example:
        Basic usage for managing blacklisted IPs::

            from .config import Config
            from .fwdb import FwDb

            cf = Config()
            db = FwDb(cf)

            # Check if IP is blacklisted
            if db.lookup_by_ip('192.0.2.1'):
                print("IP is blacklisted")

            # Clean entries older than 7 days with low incident counts
            import time
            week_ago = int(time.time()) - 7 * 86400
            db.clean(week_ago, incidents=2, matchcount=5)

    See Also:
        sqdb.SqDb: Base class for SQLite database operations
        blacklist: Module that scans logs and populates this database
    """

    def __init__(self, cf: Config, createdb: bool = True) -> None:
        """Initialize the firewall database.

        Creates or connects to the blacklist database and ensures the schema
        exists. The database file location is determined by the Config instance.

        Args:
            cf: Config instance providing database path and settings
            createdb: If True, create database/tables if they don't exist.
                     If False, assume database exists and skip creation.

        Note:
            The blacklist table uses an integer column 'useall' to store boolean
            values due to SQLite's lack of native boolean type. 0 = False, 1 = True.
        """
        create = """CREATE TABLE blacklist
                    (ip TEXT UNIQUE PRIMARY KEY, pattern TEXT,
                    incidents INT, matchcount INT,
                    first INT, last INT, ports TEXT,
                    useall INT, multiple INT,
                    isdnsbl INT);
                    CREATE UNIQUE INDEX blacklist_ix ON blacklist(ip);
             """
        path = cf.varfilepath('firewall')
        if createdb:
            super().__init__(cf, path, {'blacklist': create})
        else:
            super().__init__(cf, path, None)

    def lookup_by_ip(self, ip: str) -> list[dict[str, Any]]:
        """Lookup an IP address in the blacklist table.

        Args:
            ip: IP address to search for (e.g., '192.0.2.1')

        Returns:
            List containing a single dictionary with all database fields for the IP,
            or empty list if not found. Dictionary keys match the database schema:
            ip, pattern, incidents, matchcount, first, last, ports, useall,
            multiple, isdnsbl.

        Example:
            >>> db = FwDb(cf)
            >>> results = db.lookup_by_ip('192.0.2.1')
            >>> if results:
            ...     print(f"Found IP with {results[0]['incidents']} incidents")
            ...     print(f"Ports: {results[0]['ports']}")
        """
        return self.lookup('blacklist', where='ip = ?', vals=(ip,))

    def lookup_ips_for_deletion(
        self, before: int, incidents: int = 0, matchcount: int = 0
    ) -> list[dict[str, Any]]:
        """Find IPs eligible for deletion based on age and activity thresholds.

        Searches for IPs that were last seen before the given timestamp and
        optionally meet incident/matchcount thresholds. This is used by the
        cleanup process to remove stale entries.

        Args:
            before: Unix timestamp - IPs last seen before this time are candidates
            incidents: If > 0, only include IPs with incidents <= this value
            matchcount: If > 0, only include IPs with matchcount <= this value

        Returns:
            List of dictionaries, each containing just the 'ip' field for matching
            entries. Returns empty list if none match.

        Example:
            >>> import time
            >>> week_ago = int(time.time()) - 7 * 86400
            >>> # Find IPs not seen in a week with low activity
            >>> candidates = db.lookup_ips_for_deletion(
            ...     before=week_ago, incidents=1, matchcount=3
            ... )
            >>> print(f"Found {len(candidates)} IPs for deletion")
        """
        exprlist = [('last', '<', before)]
        if incidents != 0:
            exprlist.append(('incidents', '<=', incidents))
            if matchcount != 0:
                exprlist.append(('matchcount', '<=', matchcount))
        expr, vals = self.compile_where(exprlist)
        return self.lookup('blacklist', what='ip', where=expr, vals=tuple(vals))

    def insert_ip(self, argdict: dict[str, Any]) -> int:
        """Insert a new IP record into the blacklist table.

        Args:
            argdict: Dictionary with database column values. Should include all
                    required fields: ip, pattern, incidents, matchcount, first,
                    last, ports, useall, multiple, isdnsbl.

        Returns:
            The rowid of the inserted row

        Example:
            >>> import time
            >>> now = int(time.time())
            >>> db.insert_ip({
            ...     'ip': '192.0.2.100',
            ...     'pattern': 'ssh-brute',
            ...     'incidents': 1,
            ...     'matchcount': 5,
            ...     'first': now,
            ...     'last': now,
            ...     'ports': '22',
            ...     'useall': 0,
            ...     'multiple': 0,
            ...     'isdnsbl': 0
            ... })
        """
        return self.insert('blacklist', argdict)

    def update_ip(self, argdict: dict[str, Any], ip: str) -> None:
        """Update an existing IP record in the blacklist table.

        Only the fields provided in argdict will be updated; other fields
        remain unchanged.

        Args:
            argdict: Dictionary with column names and new values to update
            ip: IP address of the record to update

        Example:
            >>> # Increment incident count and update last seen time
            >>> import time
            >>> db.update_ip({
            ...     'incidents': 2,
            ...     'matchcount': 10,
            ...     'last': int(time.time())
            ... }, '192.0.2.100')
        """
        return self.update('blacklist', argdict, 'ip', ip)

    def delete_ip(self, ip: str) -> int:
        """Delete an IP address from the blacklist database.

        Args:
            ip: IP address to remove from the database

        Returns:
            Number of rows deleted (0 if IP not found, 1 if deleted)

        Example:
            >>> deleted = db.delete_ip('192.0.2.100')
            >>> if deleted:
            ...     print("IP successfully removed from blacklist")
        """
        deleted = self.remove('blacklist', [('ip', '=', ip)])
        return deleted

    def clean(self, lasttime: int, incidents: int = 0, matchcount: int = 0) -> int:
        """Remove old entries from the database based on age and activity.

        Deletes IPs that were last seen before the specified timestamp and
        optionally meet incident/matchcount criteria. This is typically called
        during the 'tidy' operation to expire stale blacklist entries.

        Args:
            lasttime: Unix timestamp - delete IPs with last < lasttime
            incidents: If > 0, only delete IPs with incidents <= this value
            matchcount: If > 0, only delete IPs with matchcount <= this value

        Returns:
            Number of IP records deleted

        Example:
            >>> import time
            >>> # Delete entries not seen in 14 days with low activity
            >>> two_weeks_ago = int(time.time()) - 14 * 86400
            >>> deleted = db.clean(
            ...     lasttime=two_weeks_ago,
            ...     incidents=2,
            ...     matchcount=5
            ... )
            >>> print(f"Removed {deleted} stale entries")

        Note:
            The incidents and matchcount parameters are optional filters.
            If set to 0 (default), they are ignored and only the time
            criterion is used.
        """
        exprlist = [('last', '<', lasttime)]
        if incidents != 0:
            exprlist.append(('incidents', '<=', incidents))
        if matchcount != 0:
            exprlist.append(('matchcount', '<=', matchcount))
        deleted = self.remove('blacklist', exprlist)
        if deleted is None:
            deleted = 0
        return deleted

    def clean_not_in(
        self, lasttime: int, not_in_list: list[str],
        incidents: int = 0, matchcount: int = 0) -> int:
        """Remove old entries while preserving specific IPs.

        Like clean(), but preserves IPs in the not_in_list. This is useful when
        you want to clean old entries but keep certain IPs that are still active
        or important (e.g., from a whitelist).

        Args:
            lasttime: Unix timestamp - delete IPs with last < lasttime
            not_in_list: List of IP addresses to preserve (not delete)
            incidents: If > 0, only delete IPs with incidents <= this value
            matchcount: If > 0, only delete IPs with matchcount <= this value

        Returns:
            Number of IP records deleted

        Example:
            >>> import time
            >>> week_ago = int(time.time()) - 7 * 86400
            >>> # Clean old entries but preserve these specific IPs
            >>> protected_ips = ['192.0.2.1', '192.0.2.2']
            >>> deleted = db.clean_not_in(
            ...     lasttime=week_ago,
            ...     not_in_list=protected_ips,
            ...     incidents=1,
            ...     matchcount=3
            ... )
            >>> print(f"Cleaned {deleted} entries, preserved {len(protected_ips)}")

        Note:
            This method is typically used in conjunction with whitelist checking
            to ensure whitelisted IPs are never removed from the database.
        """
        exprlist = [('last', '<', lasttime)]
        if incidents != 0:
            exprlist.append(('incidents', '<=', incidents))
        if matchcount != 0:
            exprlist.append(('matchcount', '<=', matchcount))
        deleted = self.remove_not_in('blacklist', exprlist, 'ip', not_in_list)
        if deleted is None:
            deleted = 0
        return deleted
