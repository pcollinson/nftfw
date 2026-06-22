"""Blacklist management system for automated IP blocking based on log analysis.

This module provides the BlackList class which orchestrates the entire blacklist
process: scanning logs for malicious activity, maintaining an SQLite database of
offenders, creating blacklist files for the firewall, and cleaning up expired entries.

The blacklist system is event-driven and integrates with:
- Pattern-based log scanning (patternreader, logreader)
- SQLite database for tracking IP addresses and incidents (fwdb)
- Whitelist checking to prevent false positives (whitelistcheck)
- Firewall file management (blacklist.d directory)

Key Features
------------
- Automated log scanning with pattern matching
- Threshold-based IP blocking (block_after, block_all_after)
- Incident and match count tracking
- Port-specific or full blocking
- Automatic expiry of old blacklist entries
- Database cleaning with preservation of active entries
- Missing file detection and recovery
- Test mode for pattern validation
- Whitelist integration to prevent blocking legitimate IPs

Workflow
--------
1. **Log Scanning**: Uses logreader to scan logs with patterns from patterns.d
2. **Database Updates**: Stores/updates IP information in SQLite database
3. **File Creation**: Creates .auto files in blacklist.d for IPs meeting thresholds
4. **Expiry**: Removes old .auto files based on expire_after setting
5. **Cleaning**: Removes old database entries while preserving active entries

Configuration (from [Blacklist] section in config.ini)
------------------------------------------------------
- **block_after**: Minimum matchcount to create blacklist file
- **block_all_after**: Matchcount threshold to block all ports
- **expire_after**: Days before blacklist file expires
- **clean_before**: Days before database entry can be cleaned
- **clean_by_count**: Days for count-based cleaning phase
- **sync_check**: Frequency (in runs) for missing file check
- **incidents_le**: Max incidents for count-based cleaning
- **matchct_le**: Max matchcount for count-based cleaning

Usage Example
-------------
    from .config import Config
    from .blacklist import BlackList

    # Initialize configuration
    cf = Config()
    cf.readini()
    cf.setup()

    # Run blacklist scan
    bl = BlackList(cf)
    changes = bl.blacklist()
    print(f"Blacklist scan complete: {changes} files changed")

    # Test mode: scan logs without updating
    bl.blacklist_scan()

    # Clean old database entries
    bl.clean_database()

See Also
--------
logreader : Log scanning with pattern matching
patternreader : Pattern file parsing
fwdb.FwDb : Database for tracking blacklisted IPs
whitelistcheck : Whitelist validation
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any
from pathlib import Path
import time
import logging
from .logreader import log_reader, patternmerge
from .listreader import ListReader
from .fwdb import FwDb
from .whitelistcheck import WhiteListCheck
from .stats import duration, frequency

if TYPE_CHECKING:
    from .config import Config

log = logging.getLogger('nftfw')


class BlackList:
    """Manages IP blacklisting based on log analysis and pattern matching.

    This class coordinates the entire blacklist workflow: scanning logs for
    malicious activity, maintaining a database of offending IPs, creating
    firewall blacklist files, expiring old entries, and cleaning the database.

    The system uses thresholds to determine when to block IPs and supports
    both port-specific and full blocking. It integrates with whitelist checking
    to prevent blocking legitimate IPs.

    Attributes:
        cf: Config instance with all settings
        blacklistpath: Path to blacklist.d directory
        file_create: If True, create blacklist files (False for nftfwedit)
        report_whitelisting: If True, log errors for whitelisted IPs
        block_after: Minimum matchcount to create blacklist file
        block_all_after: Matchcount threshold to block all ports
        expire_after: Days before blacklist file expires
        clean_before: Days before database entry can be cleaned
        sync_check: Frequency (in runs) for missing file check
        clean_by_count: Days for count-based cleaning phase
        incidents_le: Max incidents for count-based cleaning
        matchct_le: Max matchcount for count-based cleaning

    Example:
        Basic usage for blacklist scanning::

            from .config import Config
            from .blacklist import BlackList

            cf = Config()
            cf.readini()
            cf.setup()

            bl = BlackList(cf)

            # Run full blacklist scan
            changes = bl.blacklist()

            # Or scan without updating (test mode)
            bl.blacklist_scan()

            # Clean database periodically
            bl.clean_database()

    See Also:
        logreader: Log scanning module
        fwdb.FwDb: Database management
        whitelistcheck: Whitelist validation
    """

    # pylint: disable=too-many-instance-attributes
    # but we need them here

    def __init__(self, cf: Config) -> None:
        """Initialize the BlackList instance with configuration.

        Args:
            cf: Config instance containing all blacklist settings

        Note:
            Loads configuration values from [Blacklist] section including
            thresholds for blocking, expiry, and cleaning parameters.
        """
        self.cf = cf
        # Path to blacklist.d
        self.blacklistpath: Path = cf.etcpath('blacklist')
        # Ini values used
        logvars = cf.get_ini_values_by_section('Blacklist')
        # set to false in nftfwedit
        self.file_create = True
        # log error if ip is whitelisted
        self.report_whitelisting = False

        self.block_after = int(logvars['block_after'])
        self.block_all_after = int(logvars['block_all_after'])
        self.expire_after = int(logvars['expire_after'])
        self.clean_before = int(logvars['clean_before'])
        self.sync_check = int(logvars['sync_check'])
        self.clean_by_count = int(logvars['clean_by_count'])
        self.incidents_le = int(logvars['incidents_le'])
        self.matchct_le = int(logvars['matchct_le'])

    def blacklist(self) -> int:
        """Main entry point for blacklist scanning from scheduler.

        Performs the complete blacklist workflow:
        1. Scan logs for malicious activity (log_reader)
        2. Install IPs meeting thresholds
        3. Check for missing blacklist files (if sync_check enabled)
        4. Expire old blacklist files

        Returns:
            Number of files changed (created, updated, or deleted)

        Example:
            >>> bl = BlackList(cf)
            >>> changes = bl.blacklist()
            >>> print(f"Files changed: {changes}")

        Note:
            - Can be disabled by creating 'disabled' file in blacklist.d
            - Logs info messages for scan start/end and match counts
            - All file operations are batched for performance
        """
        # symbiosis allows a file called disabled
        # in the blacklist directory to stop things happening
        disabled = self.blacklistpath / 'disabled'
        if disabled.exists():
            return 0

        log.info("Blacklist scan starts")

        # Want to make file creation/deletion
        # happen as fast as possible
        # so cache all the actions
        # and do them in a loop at the end

        # count changes
        changes = 0

        work = log_reader(self.cf)
        if any(work):
            changes, ipsmatched = self.install_ips(work)
            log.info('Blacklist matches: %s', ipsmatched)

        # Missing sync code
        # don't run if disabled
        if self.sync_check != 0:
            changes += self.scan_for_missing()

        # Expiry code
        log.info("Blacklist expiry scan")
        changes += self.scan_for_expires()

        log.info('Blacklist scan ends - changes: %d', changes)

        return changes

    def blacklist_scan(self) -> None:
        """Scan logs and display matches without updating anything.

        Test mode entry point (invoked with -x flag) that scans logs with
        patterns but doesn't update file positions, database, or create
        blacklist files. Results are displayed in a formatted table.

        Example:
            >>> bl = BlackList(cf)
            >>> bl.blacklist_scan()
            +----------------+------------+-------+--------+
            | IP             | Pattern    | Count | Ports  |
            +----------------+------------+-------+--------+
            | 192.0.2.1      | ssh-brute  | 15    | 22     |
            | 192.0.2.2      | http-scan  | 5     | 80,443 |
            +----------------+------------+-------+--------+

        Note:
            - Uses prettytable for output formatting
            - Doesn't update log file positions
            - Useful for testing pattern files before deployment
        """
        # Dynamic load, pretty table is not always needed
        # but pylint may complain on bullseye with import-outside-toplevel
        # pylint: disable=import-outside-toplevel
        from prettytable import PrettyTable

        work = log_reader(self.cf, update_position=False)
        if not any(work):
            print("No matches")
            return
        # make list sorted by pattern name
        pt = PrettyTable()
        pt.field_names = ['IP', 'Pattern', 'Count', 'Ports']

        for ip, v in work.items():
            if isinstance(v['ports'], str):
                ports = v['ports']
            else:
                ports = ",".join(map(str, v['ports']))
            pt.add_row([str(ip),
                        v['pattern'],
                        v['matchcount'],
                        ports])
        # set up format
        pt.align = 'l'
        print(pt)

    def install_ips(self, work: dict[str, dict[str, Any]]) -> tuple[int, int]:
        """Install IPs that have triggered pattern matches.

        Processes log scan results, validates IPs (whitelist check), updates
        database, and creates blacklist files for IPs meeting thresholds.

        Args:
            work: Dictionary mapping IP addresses to match information::

                {
                    'ip_address': {
                        'ports': 'all' | 'test' | 'update' | [22, 80, ...],
                        'pattern': 'pattern_name',
                        'matchcount': 5,
                        'incidents': 2
                    }
                }

        Returns:
            Tuple of (filesinstalled, ipsmatched)::

                filesinstalled: Number of blacklist files created/updated
                ipsmatched: Number of valid IPs processed

        Example:
            >>> work = log_reader(cf)
            >>> files_created, ips_processed = bl.install_ips(work)
            >>> print(f"Created {files_created} files for {ips_processed} IPs")

        Note:
            - Skips whitelisted and invalid IPs
            - Skips IPs with ports='test' (test mode only)
            - Updates database for all valid IPs
            - Only creates files if self.file_create is True
        """
        fwdb = FwDb(self.cf)
        filesinstalled = 0
        ipsmatched = 0

        # want to ignore any whitelisted IPs
        # this class opens NormaliseAddress
        # and we'll use that to get the address
        # into a form we want
        wlchk = WhiteListCheck(self.cf)

        for ip, patinfo in work.items():

            # need to sort out ips
            # only blacklist global ips
            # and not if they are whitelisted
            test_ip = wlchk.normalise_addr.normal(ip, is_white=wlchk.is_white)
            if test_ip is None:
                if self.report_whitelisting:
                    log.error("%s is either an illegal format, or is whitelisted", ip)
                continue
            ip = test_ip
            ipsmatched += 1
            log.info("%s match count %d from %s", ip,
                     patinfo['matchcount'], patinfo['pattern'])

            # just report matches for 'test'
            if patinfo['ports'] == 'test':
                continue

            # update the database
            current, ports_have_changed = self.db_store(fwdb, ip, patinfo)

            # will be none if update only but not in database
            if current is None:
                log.error("%s database update from %s - not in database",
                          ip, patinfo['pattern'])
            elif self.file_create:
                # update file - allow the nftfwedit 'add' code to
                # use this code without adding a file
                filesinstalled += self.install_file(fwdb, current, ports_have_changed)

        fwdb.close()
        return filesinstalled, ipsmatched

    def db_store(self, fwdb: FwDb, ip: str,
                 patinfo: dict[str, Any]) -> tuple[dict[str, Any] | None, bool]:
        """Update database with IP and pattern match information.

        Creates new database entry for first-time offenders or updates existing
        entries with new match counts, patterns, and ports. Handles port
        aggregation across multiple pattern matches.

        Args:
            fwdb: FwDb database instance
            ip: IP address (already validated and normalised)
            patinfo: Pattern match information::

                {
                    'ports': 'all' | 'test' | 'update' | [22, 80, ...],
                    'pattern': 'pattern_name',
                    'matchcount': 5,
                    'incidents': 2
                }

        Returns:
            Tuple of (current, ports_have_changed)::

                current: Database record dict or None if update-only and not in DB
                ports_have_changed: True if ports were modified

        Example:
            >>> fwdb = FwDb(cf)
            >>> patinfo = {'ports': [22], 'pattern': 'ssh', 'matchcount': 5, ...}
            >>> record, changed = bl.db_store(fwdb, '192.0.2.1', patinfo)
            >>> if changed:
            ...     print("Ports were updated")

        Note:
            - Returns (None, None) for update-only IPs not in database
            - Logs frequency information for existing entries
            - Aggregates ports across multiple matches
            - Maintains comma-separated pattern list
        """
        # pylint: disable=too-many-locals,too-many-branches

        # Flag used for file update
        ports_have_changed = False
        # Now let's lookup this ip in the database
        lookup = fwdb.lookup_by_ip(ip)
        if not any(lookup):
            # not found cannot update
            if patinfo['ports'] == 'update':
                return None, False

            # make ports into a single string
            # ports will now be 'all' or numeric list
            ports = patinfo['ports']
            if not isinstance(ports, str):
                ports = ",".join(map(str, ports))

            # need a new record
            tnow = fwdb.db_timestamp()
            current: dict[str, Any] = {'ip': ip,
                                       'pattern': patinfo['pattern'],
                                       'incidents': patinfo['incidents'],
                                       'matchcount': patinfo['matchcount'],
                                       'first': tnow,
                                       'last': tnow,
                                       'ports': ports,
                                       'useall': False,
                                       'multiple': False,
                                       'isdnsbl': False}
            fwdb.insert_ip(current)
        else:
            # we have a record
            # assume that only 1 will match
            # we have a constraint in sqlite to ensure that
            current = lookup[0]
            tnow = fwdb.db_timestamp()
            update: dict[str, Any] = {}

            # Log an idea of frequency since last report
            self.log_frequency(ip, patinfo['matchcount'],
                               current['last'], tnow)

            # update counts
            for k in ('incidents', 'matchcount'):
                current[k] = current[k] + patinfo[k]
                update[k] = current[k]

            # check on patterns
            # maintain comma separated list
            # logreader can now generate comma separated lists
            update['pattern'] = patternmerge(current['pattern'], patinfo['pattern'])

            # old code replaced
            #if patinfo['pattern'] \
            #   and patinfo['pattern'] != '':
            #    patlist = current['pattern'].split(',')
            #    if patinfo['pattern'] not in patlist:
            #        patlist.append(patinfo['pattern'])
            #        update['pattern'] = ",".join(patlist)
            #        current['pattern'] = update['pattern']

            # now look at ports
            ports = current['ports']
            ports_have_changed = False

            # Update ports in the record
            # and from thence into the firewall
            #
            # We have current ports in database in ports
            #    can be a string: all
            #       or a string that's a numeric list
            #
            # newports from rule in patinfo['ports']
            #     can be a string: update or all
            #       or a numeric list
            #
            # Strategy:
            # 1. Do nothing here if newports == update
            #    or current ports == all
            # 2. If newports == all then set that into
            #    the record
            # 3. Use sets to compare the two lists
            #    if different merge the lists into one
            #    and use that

            newports = patinfo['ports']

            if newports != 'update' \
               and ports != 'all':
                if newports == 'all':
                    current['ports'] = 'all'
                    ports_have_changed = True
                else:
                    # make two sets
                    portset = set(map(int, ports.split(',')))
                    newset = set(newports)
                    if portset != newset:
                        al = list(portset.union(newset))
                        current['ports'] = ",".join(map(str, sorted(al)))
                        ports_have_changed = True

            if ports_have_changed:
                update['ports'] = current['ports']

            update['last'] = tnow
            fwdb.update_ip(update, ip)

        return current, ports_have_changed

    @staticmethod
    def log_frequency(ip: str, matchcount: int, first: int, last: int) -> None:
        """Log frequency information for repeated matches.

        Calculates and logs the duration and frequency of matches for an IP
        to help understand attack patterns.

        Args:
            ip: IP address
            matchcount: Number of new matches
            first: Unix timestamp of last recorded incident
            last: Unix timestamp of current incident

        Example:
            >>> bl.log_frequency('192.0.2.1', 10, 1699564800, 1699568400)
            # Logs: "192.0.2.1 count 10 in 1 hour - 10 per hour"

        Note:
            - Uses stats.duration() and stats.frequency() for formatting
            - Only logs if time difference is meaningful
            - Logs count only if frequency calculation not possible
        """
        if first >= last:
            return

        dur = duration(first, last)
        if dur == '':
            return

        freq = frequency(first, last, matchcount)

        if freq == '':
            log.info('%s count %d in %s', ip, matchcount, dur)
        else:
            log.info('%s count %d in %s - %s', ip, matchcount, dur, freq)

    def install_file(self, fwdb: FwDb, current: dict[str, Any],
                     ports_have_changed: bool) -> int:
        """Create or update blacklist file for an IP address.

        Checks thresholds and creates .auto file in blacklist.d if IP meets
        blocking criteria. Handles port specification and useall flag for
        high-frequency offenders.

        Args:
            fwdb: Database instance for timestamp and updates
            current: Database record for the IP::

                {
                    'ip': '192.0.2.1',
                    'pattern': 'ssh-brute',
                    'incidents': 2,
                    'matchcount': 15,
                    'first': 1699564800,
                    'last': 1699568400,
                    'ports': '22' or 'all',
                    'useall': False,
                    'multiple': False,
                    'isdnsbl': False
                }

            ports_have_changed: Force file rewrite if True

        Returns:
            1 if file was created/modified, 0 otherwise

        Example:
            >>> record = fwdb.lookup_by_ip('192.0.2.1')[0]
            >>> changed = bl.install_file(fwdb, record, False)
            >>> if changed:
            ...     print("Blacklist file created/updated")

        Note:
            - Returns 0 if matchcount < block_after threshold
            - Sets useall flag if matchcount >= block_all_after
            - Skips if raw (non-.auto) file exists
            - Touches file to update mtime if no changes needed
            - Replaces '/' with '|' in filenames for CIDR notation
        """
        # force types - values from the db may be strings
        if current['matchcount'] < self.block_after:
            return 0

        if current['matchcount'] >= self.block_all_after:
            # need to block all for this ip
            if not current['useall']:
                args: dict[str, Any] = {'useall': True}
                args['last'] = fwdb.db_timestamp()
                fwdb.update_ip(args, current['ip'])
                # force useall on for later
                current['useall'] = True
                ports_have_changed = True

        # need to setup the file base
        bld = self.blacklistpath

        # Set up file stem
        fname = current['ip']
        # ensure that masks are stored as '|'
        fname = fname.replace('/', '|')
        ipfile = bld / fname

        # return if raw file exists
        if ipfile.exists():
            return 0

        # otherwise we need to create ip.auto
        fname = fname + '.auto'
        ipfile = bld / fname

        # set up ports the useall flag allows setting up file
        # contents, while retaining port values in the database useall
        # can be forced on above as counter state changes

        if current['ports'] == 'all' \
           or current['useall']:
            ports = 'all'
        else:
            ports = current['ports']

        # if the file doesn't file exist or the ports have changed,
        # write the file otherwise update mtime using touch

        if not ipfile.exists() \
           or ports_have_changed:
            p = '\n'.join(ports.split(','))
            self.write(ipfile, p+'\n')
            log.info("%s created from %s", fname, current['pattern'])
            return 1

        self.touch(ipfile)
        log.info("%s updated from %s", fname, current['pattern'])
        return 0

    def scan_for_missing(self) -> int:
        """Check for missing blacklist files and recreate them.

        Event-driven systems can miss events, so this periodically scans the
        database for IPs that should have blacklist files but don't. Uses
        sync_check frequency to avoid checking on every run.

        Returns:
            Number of files created

        Example:
            >>> installed = bl.scan_for_missing()
            >>> if installed:
            ...     print(f"Recreated {installed} missing blacklist files")

        Note:
            - Only runs every sync_check runs (tracked in missingsync file)
            - Checks IPs active within expire_after - 1 days
            - Only checks IPs with matchcount >= block_after
            - Skips raw files, only creates .auto files
            - Uses threshold one day less than expiry to catch edge cases
        """
        # calculate threshold time
        included = self.expire_after - 1
        threshold = int(time.time()) - included*86400

        # get records to check
        fwdb = FwDb(self.cf)
        # need the whole record to install the file
        datalist = fwdb.lookup('blacklist',
                               where='last >= ? AND matchcount >= ?',
                               vals=(threshold, self.block_after))
        # bail if no data at present
        if not any(datalist):
            fwdb.close()
            return 0

        # get the number of runs from the file in sysvar
        # work out if we need to run the scan
        missingsync = self.cf.varfilepath('missingsync')
        checkdata = False
        if not missingsync.exists():
            syncval = 0
            checkdata = True
        else:
            syncval = int(missingsync.read_text(encoding='utf-8'))
            if syncval > self.sync_check:
                checkdata = True
                syncval = 0
        syncval += 1
        missingsync.write_text(str(syncval), encoding='utf-8')

        if not checkdata:
            fwdb.close()
            return 0

        log.info('Running missing blacklist ip file check')
        # create the files if missing
        installed = 0
        bld = self.blacklistpath
        for ipentry in datalist:
            ip = ipentry['ip']
            fname = ip.replace('/', '|')
            # ignore raw file if it exists
            path = bld / fname
            if path.exists():
                continue
            # otherwise it's an .auto file
            fname = fname + '.auto'
            path = bld / fname
            if not path.exists():
                log.error('Install missing blacklist ip file %s', str(fname))
                installed += self.install_file(fwdb, ipentry, True)
        fwdb.close()
        return installed

    def scan_for_expires(self) -> int:
        """Expire and remove old blacklist files.

        Scans blacklist.d for .auto files older than expire_after days and
        removes them. This allows IPs to "age out" of the blacklist.

        Returns:
            Number of files removed

        Example:
            >>> expired = bl.scan_for_expires()
            >>> print(f"Expired {expired} old blacklist files")

        Note:
            - Only removes .auto files (preserves manual entries)
            - Uses file mtime for age determination
            - Logs each expired file
            - Glob pattern '[0-9a-z]*.auto' matches IP address files
        """
        bld = self.blacklistpath

        threshold = int(time.time()) - self.expire_after * 86400
        changes = 0
        for p in bld.glob('[0-9a-z]*.auto'):
            if int(p.stat().st_mtime) < threshold:
                p.unlink()
                log.info('Blacklist %s expired', p.stem)
                changes += 1
        return changes

    def clean_database(self) -> None:
        """Clean old entries from the database in two phases.

        Phase 1: Remove entries with low activity (clean_by_count days old
                 with incidents <= incidents_le AND matchcount <= matchct_le)
        Phase 2: Remove all entries older than clean_before days

        Preserves database entries for IPs currently in the firewall.
        Runs VACUUM after deletion to optimise database.

        Example:
            >>> bl.clean_database()
            # Logs: "Blacklist database clean ends - total deleted 42"

        Note:
            - Phase 1 is skipped if clean_by_count is 0
            - Phase 2 is skipped if clean_before is 0
            - Only vacuums if deletions occurred
            - Protects active firewall entries from deletion
        """
        log.info('Blacklist database clean started')

        # Phase 1
        deleted = 0
        # do clean by counts if timeout is not zero
        # and incidents_le and in
        if self.clean_by_count != 0:
            # don't bother if both counts are zero
            if self.incidents_le + self.matchct_le != 0:
                log.info(
                    'Process entries: older than %d days & incidents <= %d, matchct <= %d',
                    self.clean_by_count,
                    self.incidents_le,
                    self.matchct_le)

                deleted = self.do_clean_db(self.clean_by_count,
                                           incidents=self.incidents_le,
                                           matchcount=self.matchct_le)

        # Phase 2
        # do clean with clean_before
        if self.clean_before != 0:
            log.info(
                'Process entries older than %d days',
                self.clean_before)
            deleted = deleted + self.do_clean_db(self.clean_before)

        # Finally
        if deleted > 0:
            # optimise the database
            fwdb = FwDb(self.cf)
            fwdb.vacuum()
            log.info("Blacklist database clean ends - total deleted %d",
                     deleted)
        else:
            log.info("Blacklist database clean ends")

    def do_clean_db(self, days: int, incidents: int = 0,
                    matchcount: int = 0) -> int:
        """Perform database cleaning with optional threshold filters.

        Deletes database entries older than specified days, optionally
        filtering by incident and matchcount thresholds. Preserves entries
        for IPs currently active in the firewall.

        Args:
            days: Delete entries with last activity older than this many days
            incidents: If > 0, only delete if incidents <= this value
            matchcount: If > 0, only delete if matchcount <= this value

        Returns:
            Number of database records deleted

        Example:
            >>> # Delete low-activity entries older than 30 days
            >>> deleted = bl.do_clean_db(30, incidents=1, matchcount=5)
            >>> print(f"Deleted {deleted} records")

        Note:
            - Adjusts timestamp for local timezone (uses time.altzone)
            - Gets active IPs from blacklist.d via ListReader
            - Uses clean() if no active IPs need preservation
            - Uses clean_not_in() to preserve active IPs
            - Returns 0 if no candidates for deletion
        """
        # returned value
        deleted = 0

        # before we start messing around, let's see if we have any work
        # get a list of candidates for deletion
        before = int(time.time()) - days*24*60*60
        # the timestamp stored is seconds from epoch
        # it's a bit less confusing for people looking at deletions
        # happening at locally adjusted times if the time delay
        # is adjusted for local timezone
        # altzone returns the difference in seconds west of UTC
        # so will be -ve for times east of GMT
        if time.daylight:
            before = before - time.altzone

        fwdb = FwDb(self.cf)
        poss = fwdb.lookup_ips_for_deletion(before,
                                            incidents=incidents,
                                            matchcount=matchcount)
        if any(poss):
            # get list of ips from db output
            possibles = [keys['ip'] for keys in poss]

            # Get the current files in the blacklist directory
            # we can use ListReader for this
            lr = ListReader(self.cf, 'blacklist', need_compiled_ix=False)

            # srcdict contains list of IP addresses and the ports that
            # they use  We just need the keys
            installedips = lr.srcdict.keys()

            # use sets to see if there is an intersection
            pset = set(possibles)
            iset = set(installedips)
            cannotdelete = pset.intersection(iset)

            # if nothing in the intersection then we can delete all
            if not any(cannotdelete):
                dels = fwdb.clean(before,
                                  incidents=incidents,
                                  matchcount=matchcount)
            else:
                # life is more complicated
                dels = fwdb.clean_not_in(before, list(cannotdelete),
                                         incidents=incidents,
                                         matchcount=matchcount)

            if dels is not None \
               and dels != 0:
                deleted = dels
                log.info('%d records removed from the database', deleted)

        fwdb.close()
        return deleted

    def write(self, path: Path, contents: str) -> None:
        """Write file contents and ensure correct ownership.

        Args:
            path: Path to file to write
            contents: Content to write to file

        Note:
            Sets ownership based on cf.fileuid/filegid after writing.
        """
        path.write_text(contents, encoding='utf-8')
        self.cf.chownpath(path)

    def touch(self, path: Path) -> None:
        """Touch file to update mtime and ensure correct ownership.

        Args:
            path: Path to file to touch

        Note:
            Sets ownership based on cf.fileuid/filegid after touching.
        """
        path.touch()
        self.cf.chownpath(path)
