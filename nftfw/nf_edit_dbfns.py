""" nftfwedit - Implement functions to support database actions"""

import logging
from normaliseaddress import NormaliseAddress
from fwdb import FwDb
from blacklist import BlackList
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
        """

        # create a worklist for blacklist
        template = {
            'ports': self.port,
            'pattern': self.pattern,
            'matchcount': 1,
            'incidents': 1
            }

        normalise = NormaliseAddress(self.cf, 'nftfwedit add')
        iplist = self.normalise_ip_list(normalise, iplist)
        if iplist is None:
            return

        # use blacklist.py methods
        bl = BlackList(self.cf)
        fwdb = FwDb(self.cf)

        # check and convert IP addresses
        for ip in iplist:
            # check if the ip is in the database
            indb = fwdb.lookup_by_ip(ip)
            if any(indb):
                log.error('%s is already in the database', ip)
            else:
                # add this ip
                bl.db_store(fwdb, ip, template, forcenew=True)
                log.info('%s added to database', ip)

        fwdb.close()

    def blacklist(self, iplist):
        """Add a set of blacklist directory as .auto

        If necessary, add the ip the blacklist database by using add
        and if so will need port and pattern set

        Makes use of methods from blacklist.py to
        do the hard stuff

        Return number of files added
        """

        normalise = NormaliseAddress(self.cf, 'nftfwedit blacklist')
        iplist = self.normalise_ip_list(normalise, iplist)
        if iplist is None:
            return 0

        fwdb = FwDb(self.cf)

        bl = BlackList(self.cf)

        # Generate database entries for update
        # use work to retain database values
        work = {}
        toadd = []
        for ip in iplist:
            # check if the ip is in the database
            indb = fwdb.lookup_by_ip(ip)
            if any(indb):
                # will only be one
                work[ip] = indb[0]
            else:
                toadd.append(ip)

        # any ips need adding?
        if any(toadd):
            # we need port or pattern
            if self.port is None \
               or self.pattern is None:
                ipe = ", ".join(toadd)
                log.error('Pattern or port needed for %s', ipe)
                fwdb.close()
                return 0

            # dbstore template
            template = {
                'ports': self.port,
                'pattern': self.pattern,
                'matchcount': 1,
                'incidents': 1
            }
            for ip in toadd:
                current = bl.db_store(fwdb, ip, template, forcenew=True)[0]
                work[ip] = current
                log.info('%s added to database', ip)

        # create files
        added = 0

        for ip in iplist:
            current = work[ip]
            # fake matchcount
            current['matchcount'] = int(bl.block_after)
            added += bl.install_file(fwdb, current, True)
            log.info('%s added to blacklist.d', ip)

        fwdb.close()
        return added

    def delete(self, iplist):
        """Delete a list of ipaddresses address from the database

        Also deletes from the blacklist.d directory if there

        Parameters
        ----------
        iplist : List[str]

        Returns
        -------
        int
            Number of files deleted
        """

        normalise = NormaliseAddress(self.cf, 'nftfwedit delete')
        iplist = self.normalise_ip_list(normalise, iplist)
        if iplist is None:
            return 0

        blacklistpath = self.cf.etcpath('blacklist')

        fwdb = FwDb(self.cf)

        # do database update first
        ipsdeleted = 0
        filesdeleted = 0
        for ip in iplist:
            indb = fwdb.lookup_by_ip(ip)
            if any(indb):
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
            Return list of addresses
            None on any errors
        """

        added = []
        for ip in iplist:
            newip = normalise.normal(ip)
            if newip is not None:
                added.append(newip)

        if len(added) != len(iplist):
            return None
        return added
