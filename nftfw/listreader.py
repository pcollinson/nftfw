#!/usr/bin/env python3
"""nftfw ListReader class

Reads files from whitelist.d and blacklist.d directories generating a
data structure.

Also contains SetName: a class used to make nftables set names.
"""

import re
import ipaddress
import logging
log = logging.getLogger('nftfw')

class ListReader:
    """ ListReader class

    when initialised reads files from either whitelist and blacklist
    directories

    Each file in these directories is named by an ip or ip6 address,
    possibly followed by '.auto' Names can contain a vertical bar and
    a mask number - ip6 addresses are usually /112.

    Contents of the file is a set of ports, one per line

    Attributes
    ----------

    srcdict : Dict[ip:contents]
        Reads data from {whitelist,blacklist}.d and loads
        ip : str
            IP address from the directory
        contents: str
            Comma separated list of ports
            from the file - or perhaps 'all'

        Various modules use this raw form to read whitelist
        directory contents

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

    def __init__(self, cf, listname, need_compiled_ix=True):
        """Initialise with cf to find constant locations

        Parameters
        ----------
        cf : Config
        listname : {'whitelist', 'blacklist}
        need_compiled_ix : bool
            False if caller just needs srcdict

        Creates srcdict and records
        """

        self.cf = cf
        self.listname = listname
        self.path = cf.etcpath(listname)
        self.srcdict = self.loadfile()
        if need_compiled_ix:
            self.records = self.compileix(self.srcdict)


    def loadfile(self):
        """Create srcdict by reading the directory

        Validate any port settings in the file creating
        comma separated numerically sorted list

        Returns
        -------
        srcdict : Dict
            may be empty

        """

        # symbiosis allows a file called disabled to exist to
        # stop list compilation
        disabled = self.path / 'disabled'
        if disabled.exists():
            return {}

        # re matches
        # sequence of 0-9a-f . or : as far as it can
        #     captured in match[1]
        # followed optionally by | and one, two or three digits
        #     captured in match[2]
        # followed optionally by .auto
        strict = re.compile(r'([0-9a-f.:]*?)(\|[0-9]{1,3})?(?:\.auto)?$', re.I)
        srcdict = {}
        for p in sorted(self.path.glob('[0-9a-z]*')):
            ma = strict.match(p.name)
            if ma is not None and p.is_file():
                key = ma.group(1)
                if ma.group(2) is not None:
                    key = key + '/' + ma.group(2)[1:]
                ports = p.read_text()
                srcdict[key] = self.portcheck(ports)
        return srcdict

    def compileix(self, srcdict):
        """Massage raw information from srcdict into records

        Validates ip and ip6 addresses
        Uses the SetName class to create a name for the sets

        Returns
        -------
        records - see Attributes comment
        """

        master = {}
        for ip, ports in srcdict.items():
            ipv = self.validateip(ip)
            if ipv is not None:
                if ports not in master:
                    master[ports] = {}
                if ipv.version == 4:
                    proto = 'ip'
                else:
                    proto = 'ip6'
                if proto not in master[ports]:
                    master[ports][proto] = []
                if str(ipv) not in master[ports][proto]:
                    master[ports][proto].append(str(ipv))
        # now deal with names for the entries§
        # initialise the name generator
        setname = SetName(self.listname)
        for ports in master:
            name = setname.name(ports)
            master[ports]['name'] = name
        return master

    @staticmethod
    def portcheck(ptstr):
        """Check and validate port list from string

        Check file contents:

        If list is empty - return 'all'
        If contents contains 'all' return 'all'
        Otherwise it should be a numeric list
        one per line

        Make into a sorted list
        return as comma separated
        ignore any blank lines, and lines
        which don't contain numeric values

        Parameters
        ----------
        ptstr : str
            Ports on several lines with possible white space

        Returns
        -------
        str
            Cleaned and validated comma separated list of ports
        """

        # look for 'all' in contents
        if 'all' in ptstr.casefold():
            return 'all'
        # make an array of ints so we can sort them
        # shouldn't have commas, but people may type them
        pt = ptstr.replace(',', '\n')
        # split at newlines also lose any whitespace
        li = [n.strip() for n in pt.split("\n")
              if n.strip().isnumeric()]
        if any(li):
            li = list(set(li))
            li = sorted(li, key=int)
            return ','.join(li)
        return 'all'

    def validateip(self, ip):
        """Validate the ipaddress

        Parameters
        ----------
        ip: str

        Returns
        -------
        ipaddress
        returns ipaddress class instance so version can be checked
        """
        try:
            if '/' in ip:
                i = ipaddress.ip_network(ip, strict=False)
            else:
                i = ipaddress.ip_address(ip)
            return i
        except ValueError as e:
            log.error('%s: %s: %s', self.path, ip, str(e))
            return None


class SetName:
    """SetName makes names for sets

    The plan is to use nftables sets to block the lists of IP addresses
    that ListReader generates. There is nothing in the Symbiosis API to
    make this easy, so the names will be:

    prefix character (either b or w) for blacklist and whitelist an
    underscore then the ports that are to be matched with separated by
    '_'.

    However, names are limited to 16 characters, so there needs to be
    some way to generate names in case of clashes. This is be done by
    adding a digit after the prefix character.
    """

    def __init__(self, listname):
        """SetName initialise

        Parameters
        ----------
        listname : str
            called with listname so first character can be used as the
            name prefix
        """

        self.prefix = listname[:1]
        #
        # Dict to remember lookups and store prefix values
        self.checkdict = {}

    def name(self, ports):
        """Generate a name from ports

        Parameters
        ----------
        ports : str
            a comma separated string
        """

        portsname = "_".join(ports.split(","))
        return self.mkname('', portsname)

    def mkname(self, seq, body):
        """Make the name fit into 16 characters

        A recursive function - but shouldn't
        recurse that often.

        Parameters
        ----------
        seq : str
            Sequence number or '' to start with
        body : str
            The desired body of the name to be used
        """

        mainlen = len(seq) + len(body)
        if mainlen > 14:
            body = body[:14-mainlen]
        trial = self.namefmt(seq, body)
        if trial in self.checkdict.keys():
            # we've had this before
            seqno = self.checkdict[trial]
            if seqno == '':
                seqno = 0
            seqno = int(seqno) + 1
            return self.mkname(str(seqno), body)

        self.checkdict[trial] = seq
        return trial

    def namefmt(self, seq, portsname):
        """ Format the name """

        return f'{self.prefix}{seq}_{portsname}'
