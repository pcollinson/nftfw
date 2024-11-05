"""nftfw NetReader class

The blacknet.d directory can contain one or more files ending with
.nets. The files are lists of network CIDR addresses, one per line.
Files can also contain single ipaddresses.
The files can also contain comments starting with #.

The files are used to create a large blacklist denying access to
certain countries.

The source files will rarely change, at least in comparison to
blacklist files, so there is good justification for caching the
results in an internal file and just reading it when we are building
the firewall on a more than daily basis.

"""

import re
import ipaddress
import logging
from pathlib import Path
import json
log = logging.getLogger('nftfw')

class NetReader:
    """Netreader class

    Manages the caching of information from NetReaderFromFiles

    The cache is a dict saved and restored using json.
    It contains:
    files - a dict.
            Keys are names
            Values are the mtimes of the files
    ip -  the list of ipv4 addresses for network blacklisting
    ip6 - the list of ipv6 for network blacklisting

    Cache will need reloading from NetReaderFromFiles when:
    1) there is no stored cache file
    2) there is a change in the mtime of the files
    3) when new files appear
    4) when files disappear
    5) when the user forces a full install

    The class uses listprocess to generate the
    active files for nftables. Output data is in records,
    with a single 'all' key

    records: Dict[ports : Dict[content]]
        ports : str
            Comma separated list of ports that the
            content applies to
        content: Dict[
            ip : List[str]
                List of ip4 addresses - may be empty
            ip6 : List[str]
                List of ip6 addresses - may be empty
            name : str
                Name to be used for this nftables set
            ]

    """

    # the empty version of the cache
    cache = {'files': {},
             'ip' : [],
             'ip6': []}

    # output records for listprocess
    # ip and or ip6 added if used
    recordstemplate = {
        'all': {'name' : 'blacknets_set'}}

    # output record
    records = {}


    def __init__(self, cf, listname, cachefile=None):
        """Manage the cache and load the information from json
        or run NetReaderFromFiles to load things

        Called from fwmanage so presents the same calling
        interface as listreader.

        cachefile needs to be filename in a string which
        is used for testing cache management
        """

        self.cf = cf
        if cachefile is None:
            self.cachepath = cf.varfilepath('blacknets_cache')
        else:
            self.cachepath = Path(cachefile)

        blacknets_d = cf.etcpath(listname)

        # safety - check that the blacknets.d directory exists
        if not blacknets_d.exists():
            return

        needcache = True
        if self.cachepath.exists():
            self.cache = self.loadjson()
            needcache = False

        # now see if the files have changed
        files = [f for f in blacknets_d.glob('*.nets') if f.is_file()]

        if not any(files):
            # will be false if cache file is not found
            if not needcache:
                self.cachepath.unlink()
            return

        if needcache \
           or self.cf.force_full_install \
           or self.check_on_cache(blacknets_d, files):

            # need to load the cache
            nrf = NetReaderFromFiles(cf, listname, files=files)
            for ix in ('ip', 'ip6'):
                self.cache[ix] = nrf.lists[ix]

            # update file name cache
            newfiles = {}
            for file in files:
                newfiles[file.name] = int(file.stat().st_mtime)
            self.cache['files'] = newfiles

            # save the cache file
            self.savejson(self.cache)

        # set up records
        newrecord = self.recordstemplate
        if any(self.cache['ip']):
            newrecord['all']['ip'] = self.cache['ip']
        if any(self.cache['ip6']):
            newrecord['all']['ip6'] = self.cache['ip6']
        if 'ip' in newrecord['all'] \
           or 'ip6' in newrecord['all']:
            self.records = newrecord

    def check_on_cache(self, blacknets_d, files):
        """See if the cache needs reloading

        Parameters
        ----------
        blacknets_d: Path to blacknets.d directory
        files: tuple of paths with *.nets files

        Returns
        -------
        True if cache needs reloading
        False otherwise
        """

        # shorthand
        cfiles = self.cache['files']

        # First check if a file has been deleted since we were last here
        for storedname in cfiles:
            storedpath = blacknets_d / storedname
            if storedpath not in files:
                return True

        # now scan files
        for file in files:
            # new file?
            filename = file.name
            if filename not in cfiles:
                return True

            # file changed?
            mtime = int(file.stat().st_mtime)
            if mtime > cfiles[filename]:
                return True

        return False

    def loadjson(self):
        """ Load the json contents """

        contents = self.cachepath.read_text()
        jobj = json.loads(contents)
        return jobj

    def savejson(self, cache):
        """ Save the cache contents as json """

        contents = json.dumps(cache)
        self.cachepath.write_text(contents)


class NetReaderFromFiles:
    """NetReaderFromFiles class

    When initialised reads contents of *.nets files and creates
    two dicts ip_dict and ip6_dict. Keys are a tuple:
    (footprint int (see footprint fn), prefixlen)
    Values are ipaddress objects representing networks.

    """

    # storage
    # use convention set up before that 'ip' is ipv4 and 'ip6' is ipv6
    # using a dictionary to give faster unique settings
    # key is the binary version of the network address
    # used to eliminate duplicates
    nets = {'ip': {}, 'ip6': {}}

    # This is where data ends up
    lists = {'ip': [], 'ip6': []}

    # Identify the file that specifies an address
    # key is sourcefile, argument is a list of footprints
    source = {}

    def __init__(self, cf, listname, files=None):
        """Initialise the lists from files in blacknets.d

        Parameters
        ----------
        cf : Config
        listname: name of list - blacknets
        files=files: tuple of Paths to process
             if None the list is re-created here
        """

        self.cf = cf
        blacknets_d = cf.etcpath(listname)
        # re used to remove comments
        self.commentre = re.compile(r'^(.*?)#.*$')

        # allow the class to be called with no file argument
        if files is None:
            files = [f for f in blacknets_d.glob('*.nets')
                     if f.is_file()]

        if any(files):
            for file in files:
                lineno = 1
                contents = file.read_text().split('\n')
                for line in contents:
                    self.line_process(line, file, lineno)
                    lineno += 1

            for ix in ('ip', 'ip6'):
                # remove overlapping networks
                nets = self.delete_overlaps(self.nets[ix])

                nets = sorted(nets)

                # make objects into strings
                # remove prefix from /32 or /128 addresses
                self.lists[ix] = [str(self.full_address(ipt))
                                  for ipt in nets]

    def line_process(self, line, filename, lineno):
        """Process a single line from a .nets file

        Parameters
        ----------
        line: line to look at
        filename : Path object that is the name of the file
        lineno  : int line count
        """

        # cope with comments and blank lines
        ma = self.commentre.search(line)
        if ma:
            line = ma.group(1)
        # remove white space
        line = line.strip()
        if line == '':
            return

        # Pick out lines that at not cidrs
        # store_addr saves them
        if '/' not in line:
            try:
                ipt = ipaddress.ip_address(line)
                footp = self.store_addr(ipt)
                self.store_source(filename, footp)
            except ValueError as e:
                log.error('blacknets file %s, line %d: failed on %s - %s',
                          str(filename),
                          lineno,
                          line,
                          str(e))
            # all done
            return

        # There are only networks from here`
        # unless they are /32 or /128
        try:
            ipt = ipaddress.ip_network(line, strict=False)
        except ValueError as e:
            log.error('blacknets file %s, line %d: failed on %s - %s',
                      str(filename),
                      lineno,
                      line,
                      str(e))
            return

        # Ipv4 networks are ready to go, so store them
        if isinstance(ipt, ipaddress.IPv4Network):
            footp = self.store_net(ipt)
            self.store_source(filename, footp)
            return

        # Now for ipv6 addresses we have the possibility that they
        # are actually ip4 addresses using the official way of representing
        # ip4 addresses in ipv6 ie starting with ::FFFF::
        ipcheck = self.convert_to_ipv4(ipt)
        if ipcheck is None:
            footp = self.store_net(ipt)
            self.store_source(filename, footp)
        elif ipcheck == 'error':
            log.error('blacknets file %s, line %d: could not convert ipv6 to ipv4 - %s',
                      str(filename),
                      lineno,
                      str(ipt))
        else:
            footp = self.store_net(ipcheck)
            self.store_source(filename, footp)

    @staticmethod
    def convert_to_ipv4(ipt):
        """Convert an ipv6 address that's really a mapped ip4 address

        Assume that the ip address is an ipv6 net or address
        Assume that if it's ipv4 then a 'proper' mask is given

        Parameters
        ----------
        ipt : ipaddress class

        Returns
        -------
        The ipnetwork as ip4
        or None if no conversion is needed
        or 'error' if conversion fails
        """

        is_net = False
        ipcheck = ipt
        if isinstance(ipt, ipaddress.IPv6Network):
            is_net = True
            ipcheck = ipt.network_address

        # get ipv4 style
        # ipcheck is either the original ip
        # unless it's a network, when it's
        # taken from the network_address
        ipmapped = ipcheck.ipv4_mapped
        # if ipmapped is None, then it's an IPv6 network
        if ipmapped is None:
            return None

        # Construct a new ipaddress
        # add prefix below
        newip = str(ipmapped)

        # not a network
        # make a /32 network value
        if not is_net:
            newip += '/32'
        else:
            # evaluate the prefix
            newpre = 32 - (128 - ipt.prefixlen)
            if 0 < newpre <= 32:
                newip += '/' + str(newpre)
            else:
                return 'error'
        try:
            outip = ipaddress.ip_network(newip, strict=False)
        except ValueError:
            return 'error'
        return outip

    def store_net(self, ipt):
        """Save network address

        Use class type to determine the list to use

        The key is generated by get_footprint - which derives
        a single integer from the ip address and its prefix

        Parameters
        ----------
        ipt ipnetwork object

        Returns
        -------
        Footprint key - int

        """
        if ipt.version == 4:
            ix = 'ip'
            mask = 0xff
        else:
            ix = 'ip6'
            mask = 0xffff
        # Remove erronous full addresses
        # which are errors in the lists
        if ipt.prefixlen == ipt.max_prefixlen:
            possiblenet = int(ipt.network_address) & mask
            if possiblenet in (0, mask):
                return

        # prevent duplicates
        footp = self.get_footprint(ipt)
        self.nets[ix][footp] = ipt
        return footp

    def store_addr(self, ipt):
        """Store addresses as networks

        Parameters
        ----------
        ipt ipnetwork object

        Returns
        -------
        Footprint key - int

        """

        # attempt to remove erronous addresses
        # ignore full addresses which may be
        # networks
        prelen = "/32" if ipt.version == 4 else "/128"
        newip = ipaddress.ip_network(str(ipt) + prelen,
                                     strict=False)
        return self.store_net(newip)

    def store_source(self, filename, footp):
        """ Store source information
        """

        fname = filename.name
        if fname not in self.source:
            self.source[fname] = []
        self.source[fname].append(footp)

    @staticmethod
    def get_footprint(ipt):
        """Get the integer key value for the address

        This is the ipaddress as int, left shifted 8 and or'ed
        with the prefix length

        Parameters
        ----------
        ipt ipnetwork object
        """

        working = ipt.network_address
        cidr = ipt.prefixlen
        footprint = (int(working) << 8) | cidr
        return footprint

    @staticmethod
    def delete_overlaps(srcdict):
        """Remove overlapping entries

        Parameters
        ----------
        srcdict: dict of keys, ipnetworks
        """

        return (ip for ip in ipaddress.collapse_addresses(srcdict.values()))

    @staticmethod
    def full_address(ipt):
        """Net objects with full addresses into addresses """

        if ipt.prefixlen == ipt.max_prefixlen:
            return ipt.network_address
        return ipt
