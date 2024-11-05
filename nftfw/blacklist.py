"""nftfw Blacklist class

Use files in patterns.d to specify patterns. Patterns are files that
contain logfile names, ports and regular expressions to match lines in
the files. Scan logfiles for the regexes and if ips are found create
entries in sqlite3 database.

Use thresholds to create blacklist files in blacklist.d.

Expire files in blacklist.d depending on times

Provide scan-only entry

Clean the entries in the sqlite3 database

"""

import time
import logging
from .logreader import log_reader
from .listreader import ListReader
from .fwdb import FwDb
from .whitelistcheck import WhiteListCheck
from .stats import duration, frequency
log = logging.getLogger('nftfw')

class BlackList:
    """Blacklist class

    Steps:
    1. Load pattern files
    2. Scan log files using logreader, maintain database.
       Store actions to create any files in blacklist.d
    3. Check for files in blacklist.d that need expiry
    4. Update files
    5. Clean database
    """

    # pylint: disable=too-many-instance-attributes
    # but we need them here

    def __init__(self, cf):
        """Blacklist init

        Parameters
        ----------
        cf : Config

        """

        self.cf = cf
        # Path to blacklist.d
        self.blacklistpath = cf.etcpath('blacklist')
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

    def blacklist(self):
        """Black list entry point from scheduler

        Returns
        -------
        int
            Number of changed files
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

    def blacklist_scan(self):
        """Scan files for matches, don't update anything

        -x entry point from scheduler
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

    def install_ips(self, work):
        """Install IPs that have triggered matches

        Parameters
        ----------
        work : Dict[key: Dict[]]
            key: str
               ip address
            Dict[
                ports : str
                    'all', 'test', 'update',
                    List[ports]
                pattern : str
                     pattern name that was matched
                matchcount : int
                     number of matches for this events
                incidents : int
                     number of different incident sets
                ]

        Returns
        -------
        tuple
            filesinstalled : int
                Number of files installed
            ipsmatched : int
                Number of matches found
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

    def db_store(self, fwdb, ip, patinfo):
        """Update the database with info from ip and patinfo

        Parameters
        ----------
        fwdb : class
            database class
        ip : str
            ip address
        patinfo : Dict[
            ports : {'all', 'test', 'update',
                      List[ports]}
            pattern : str
                 pattern name that was matched
            matchcount : int
                 number of matches for this events
            incidents : int
                 number of different incident sets
            ]

        Returns
        -------
        tuple : (Dict[], bool)
            Database record for update (see db_update)
            ports_have_changed : bool
                Flag to tell install_file to force update
        """

        # pylint: disable=too-many-locals,too-many-branches

        # Flag used for file update
        ports_have_changed = False
        # Now let's lookup this ip in the database
        lookup = fwdb.lookup_by_ip(ip)
        if not any(lookup):
            # not found cannot update
            if patinfo['ports'] == 'update':
                return None, None

            # make ports into a single string
            # ports will now be 'all' or numeric list
            ports = patinfo['ports']
            if not isinstance(ports, str):
                ports = ",".join(map(str, ports))

            # need a new record
            tnow = fwdb.db_timestamp()
            current = {'ip': ip,
                       'pattern': patinfo['pattern'],
                       'incidents': patinfo['incidents'],
                       'matchcount': patinfo['matchcount'],
                       'first': tnow,
                       'last': tnow,
                       'ports': ports,
                       'useall': False,
                       'multiple': False,
                       'isdnsbl':False}
            fwdb.insert_ip(current)
        else:
            # we have a record
            # assume that only 1 will match
            # we have a constraint in sqlite to ensure that
            current = lookup[0]
            tnow = fwdb.db_timestamp()
            update = {}

            # Log an idea of frequency since last report
            self.log_frequency(ip, patinfo['matchcount'],
                               current['last'], tnow)

            # update counts
            for k in ('incidents', 'matchcount'):
                current[k] = current[k] + patinfo[k]
                update[k] = current[k]

            # check on patterns
            # maintain comma separated list
            if patinfo['pattern'] \
               and patinfo['pattern'] != '':
                patlist = current['pattern'].split(',')
                if patinfo['pattern'] not in patlist:
                    patlist.append(patinfo['pattern'])
                    update['pattern'] = ",".join(patlist)
                    current['pattern'] = update['pattern']

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
    def log_frequency(ip, matchcount, first, last):
        """ Log an indication of frequency of matches

        Parameters
        ----------
        ip : str
            ip address
        matchcount : int
            matchcount
        first : int
            earliest timestamp
        last : int
            last timestamp
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

    def install_file(self, fwdb, current, ports_have_changed):
        """Install file in blacklist directory

        Parameters
        ----------
        fwdb : class
            Database class instance
        current : Dict[
            ip : str
                IP address - main key
            pattern : str
                Pattern name or comma separated list of patterns
            incidents : int
                Number of incidents
            matchcount : int
                Number of pattern matches
            first : int
                Timestamp (UNIX time) of first incident
            last : int
                Timestamp (UNIX time) of last incident
            ports : str
                Comma separated list of ports
            useall: bool
                Flag to force 'all' in port setting for
                the blacklist file
            multiple : bool
                Unused
            isdnsbl : bool
                Unused
            ]
        ports_have_changed : bool
            Force write of file if true

        Returns
        -------
        int
           1 if file has changed, zero otherwise
        """

        # force types - values from the db may be strings
        if current['matchcount'] < self.block_after:
            return 0

        if current['matchcount'] >= self.block_all_after:
            # need to block all for this ip
            if not current['useall']:
                args = {'useall': True}
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

    def scan_for_missing(self):
        """ Check database for current entries and match with blacklist.d

        The system is event driven, and needs to be checked that an
        event has not been missed, meaning a file that should be in
        blacklist.d simply isn't.

        use number of days in cf.expire_after
        but we'll subtract a day in case the entry has been expired

        Returns
        -------
        int :
            Number of files installed
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
            syncval = int(missingsync.read_text())
            if syncval > self.sync_check:
                checkdata = True
                syncval = 0
        syncval += 1
        missingsync.write_text(str(syncval))

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

    def scan_for_expires(self):
        """Expire files in the blacklist directory

        use number of days in cf.expire_after

        Returns
        -------
        int
            number of changes
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


    # This code replaced in November 2024
    # now copes with two phases of delete
    def clean_database(self):
        """ Clean entries from database

        Two phases:
        1)  Remove based on incidents and matchcounts with
            time of clean_by_count
        2)  Remove based on overall time of clean_before

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


    def do_clean_db(self, days, incidents=0, matchcount=0):
        """Clean entries from database

        But not if they are active in the firewall which makes things
        somewhat more complicated. Actually this is unlikely, but let's
        cope with it anyway


        Delete when last action is before cf.clean_by_count and
           incidents <= incidents.le AND matchcount <= matchct_le
        OR when last action is before cf.clean_before days

        return number of deletions

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

    def write(self, path, contents):
        """ Write file contents and ensure ownership """

        path.write_text(contents)
        self.cf.chownpath(path)

    def touch(self, path):
        """ Touch file and ensure ownership """

        path.touch()
        self.cf.chownpath(path)
