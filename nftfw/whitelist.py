"""nftfw WhiteList class

Looks in the utmp file for logins by system users and adds a file to
the whitelist directory for the ip address of the user.

Also expires files in the whitelist directory that are older than a
specified number of days, from the config value whitelist_expiry.
Default 8 days.

Now using local utmp interface using installed libc api

"""
import time
from pathlib import Path
import ipaddress
import logging
from nftfw_utmp import Utmp, UtmpDecode
from utmpconst import *    # pylint: disable=unused-wildcard-import,wildcard-import

log = logging.getLogger('nftfw')

class WhiteList:
    """WhiteList class

    Scans the utmp file looking for logins and user names, recording
    the associated ip address.

    Remembers the time that the scan was done last in whitelist.scan
    in var/lib/nftfw

    If any new entries are found, and the ip file doesn't exists in
    whitelist, adds the appropriate file in the symbiosis whitelist
    directory

    Also expires files in the whitelist directory that are older than
    a specified number of days, from the config value
    whitelist_expiry. Default 8 days.
    """

    def __init__(self, cf):
        """Initialise WhiteList class

        Parameters
        ----------
        cf : Config
        """

        self.cf = cf
        config = cf.get_ini_values_by_section('Whitelist')
        self.wtmp_file = config['wtmp_file']
        self.whitelist_expiry = config['whitelist_expiry']
        self.whitelistpath = self.cf.etcpath('whitelist')

    def whitelist(self):
        """Scan utmp for new whitelist candidates

        Returns
        -------
        int
            Number of changes
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
                # need to make this into a /64 network
                i6 = ipaddress.IPv6Address(i)
                if i6.is_global:
                    i6 = ipaddress.IPv6Network((i6, 64), strict=False)
                    changes += self.fileinstall(str(i6))

        # expiry old entries
        log.info('whitelist expiry check')
        changes += self.expiry()
        log.info('whitelist scan end - changes: %s', changes)
        return changes

    def scan_wtmp(self):
        """Scan the wtmp file

        Starts after time returned from looking at mtime on
        the file given in sysvar/whitelist_scan, if this exists

        Returns
        -------
        tuple
            ip : List[str]
            ip6 : List[str]
            returns ip addresses per protocol
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
                    return ([], [])

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
                else:
                    ip6.append(ut.ut_addr_v6)
        utmp.endutent()

        # update the time file
        scantime.touch()
        return (ip, ip6)

    def fileinstall(self, ip):
        """Add filenames to the whitelist directory

        Uses touch to update any that are already there

        Parameters
        ----------
        ip : str
            ipaddress

        Returns
        -------
        int
            returns int(0) if nothing is done
            int(1) if a file is made or touched
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

    def expiry(self):
        """Expire automatically installed whitelist entries

        Returns
        -------
        int
            returns int(0) if nothing is done
            int(1) if a file is made or touched
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
