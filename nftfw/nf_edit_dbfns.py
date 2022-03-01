""" nftfwedit - Implement functions to support database actions"""

import logging
from .normaliseaddress import NormaliseAddress
from .fwdb import FwDb
from .blacklist import BlackList
log = logging.getLogger('nftfw')

class DbFns:
    """Provides add, delete and blacklist functions

    Designed to work on a possible list of IP
    addresses.

    Integrated with the scheduler to provide locking
    """

    def __init__(self, cf):
        """Initialise"""
        self.cf = cf
        self.port = None
        self.pattern = None
        self.matches = None

    def execute(self):
        """Scheduler access point

        Pick up commands and args from cf.editargs

        Return changes to files as int

        Values are in cf.editargs[]
        cmd : str
            Command to execute
        port : str
            Comma separated port list
        pattern : str
            Name of pattern
        iplist : List[str]
            List of ip addresses

        """

        # name of function
        cmd = self.cf.editargs['cmd']
        fn = getattr(self, cmd)
        self.port = self.cf.editargs['port']
        self.pattern = self.cf.editargs['pattern']
        self.matches = self.cf.editargs['matches']
        files = fn(self.cf.editargs['iplist'])
        if cmd == 'add':
            return 0
        return files


    def add(self, iplist):
        """Add list of ip addresses to the database

        Using port and pattern supplied into the class
        with the extant insertion code in blacklist

        Parameters
        ----------
        iplist : List[str]

        Returns
        -------
        int: Number of files added

        """

        return self.blacklist(iplist,
                              create_files=False,
                              set_min_matches=False)

    def blacklist(self, iplist, create_files=True, set_min_matches=True):
        """Add a set of blacklist directory as .auto

        If necessary, add the ip the blacklist database by using add
        and if so will need port and pattern set

        Makes use of methods from blacklist.py to
        do the hard stuff

        This code is reused by the add action, but with
        create_files = False
        which is used to set the value in the blacklist
        code that prevents file creation.

        setting set_min_matches to False prevents setting
        of matchcount to a minimum of block_after value

        Return number of files added
        """

        # pylint: disable=too-many-locals, too-many-branches

        iplist = self.ensure_legal_addresses(iplist, 'nftfwedit blacklist')
        if iplist is None:
            return 0

        fwdb = FwDb(self.cf)

        bl = BlackList(self.cf)
        bl.report_whitelisting = True
        # Inhibit file creation if wanted
        if not create_files:
            bl.create_files = False

        # Generate database entries for update
        # use work to retain database values
        # check if we need ports and patterns
        toadd = []
        current = []
        for ip in iplist:
            # check if the ip is in the database
            indb = fwdb.lookup_by_ip(ip)
            if any(indb):
                current.append(ip)
            else:
                toadd.append(ip)
        fwdb.close()

        # any ips need adding?
        if any(toadd):
            # we need port or pattern
            if self.port is None \
               or self.pattern is None:
                ipe = ", ".join(toadd)
                log.error('Pattern and port needed for %s', ipe)
                return 0

        work = {}
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
            min_count = bl.block_after
            if ip in toadd and set_min_matches:
                # for new entries start matchcount at the threshold
                if self.matches < min_count:
                    work[ip]['matchcount'] = min_count

        # do one call to install_ips to minimise whitelist checking
        added = 0
        filesinstalled, _ = bl.install_ips(work)
        if filesinstalled > 0:
            added += filesinstalled
        return added

    def delete(self, iplist, delete_from_db = True):
        """Delete a list of ipaddresses address from the database

        Also deletes from the blacklist.d directory if there is a file to be deleted

        Parameters
        ----------
        iplist : List[str]
        delete_from_db - delete the database entry if true

        Returns
        -------
        int
            Number of files deleted
        """

        iplist = self.ensure_legal_addresses(iplist, 'nftfwedit delete')
        if iplist is None:
            return 0

        blacklistpath = self.cf.etcpath('blacklist')

        fwdb = FwDb(self.cf)

        # do database update first
        ipsdeleted = 0
        filesdeleted = 0
        for ip in iplist:
            indb = fwdb.lookup_by_ip(ip)
            if delete_from_db and any(indb):
                fwdb.delete_ip(ip)
                ipsdeleted += 1

            # does file exists
            file = ip.replace('/', '|')
            file += '.auto'
            path = blacklistpath / file
            if path.exists():
                path.unlink()
                filesdeleted += 1

        fwdb.close()

        if ipsdeleted + filesdeleted > 0:
            log.info('Deleted - ips: %d, files: %d',
                     ipsdeleted, filesdeleted)

        return filesdeleted

    def remove(self, iplist):
        """ Remove a file from the blacklist.d directory
        leaving the database alone """

        return self.delete(iplist, delete_from_db = False)

    @staticmethod
    def normalise_ip_list(normalise, iplist):
        """Normalise and check ip address list
        using method in NormaliseAddress

        Parameters
        ---------
        normalise : Instance of NormaliseAddress
        iplist : List(str)
            List of IP addresses

        Returns
        -------
        List[str]
            Return list of valid addresses
        """

        added = []
        for ip in iplist:
            newip = normalise.normal(ip)
            if newip is not None:
                added.append(newip)
        return added

    def ensure_legal_addresses(self, iplist, fromwhere):
        """Normalise a list of addresses and complain
        when some are not normal

        Return a legal list
        """

        normalise = NormaliseAddress(self.cf, fromwhere)
        normal_iplist = self.normalise_ip_list(normalise, iplist)
        if len(normal_iplist) != len(iplist):
            deleted = list(set(iplist) - set(normal_iplist))
            if any(deleted):
                log.error('Does not pass validation tests: %s',
                          ", ".join(deleted))
        return normal_iplist
