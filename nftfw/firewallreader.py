"""  nftfw firewallreader class

Reads files from incoming.d and outgoing.d directories
Generates a data structure - a set of records used
by firewallprocess
"""

import socket
import re
import ipaddress
import logging
log = logging.getLogger('nftfw')

class FirewallReader:
    """FirewallReader class

    when initialised reads files from either incoming and outgoing
    directories uses rulereader to create a list of dicts of content.
    The list is ordered in execution order.

    Attributes
    ----------
    records : List[Dict[
                  sourcefile : str
                      Stem name of sourcefile
                      nn-action
                  baseaction : str
                      action value
                  contents : str
                      file contents
                  direction : {'incoming', 'outgoing'}

                Added by validation
                  action : str
                      Action needed by the rule
                  ports  : str, optional
                      Ports used by the rule
                  ip : List[str], optional
                      List of ipv4 addresses
                  ip6 : List[str], optional
                      List of ipv6 addresses
                ]]
    """

    def __init__(self, cf, direction):
        """Initialise - creating initial contents of
        records attribute

        Parameters
        ----------
        cf : Config
        direction: {'incoming', 'outgoing'}
        """

        self.cf = cf
        self.direction = direction
        path = cf.etcpath(direction)
        # enforce strict checking on the name, assisting
        # emacs users that might get ~ appended to the name
        strict = re.compile('[0-9][0-9]-[-_a-z0-9]*$', re.I)
        self.records = [{'sourcefile':p,
                         'baseaction':p.stem[3:],
                         'contents':p.read_text(),
                         'direction':direction}
                        for p in sorted(path.glob('[0-9][0-9]-*'))
                        if strict.match(p.stem) is not None
                        and p.is_file()]
        # rulesreader is loaded externally in fwmanage
        # and stored in cf so it can be shared
        self.rulesreader = cf.rulesreader
        self.validate()

    def validate(self):
        """ Validate complete data set in self.records

        Returns
        -------
        records (see Class info) replaced with the validated set
        and new values
        """

        newrecords = []
        for rec in self.records:
            # First validate action, then if contents validate them
            try:
                self.validateaction(rec)
                if rec['contents'] != '':
                    self.validatecontents(rec)
                newrecords.append(rec)
            except OSError as e:
                # getservbyname failing - so rule isn't valid
                log.error('%s: %s', rec['sourcefile'], str(e))
        self.records = newrecords

    def validateaction(self, f):
        """Validate a single file action

        Parameters
        ----------
        f : Dict[]
            Single record to work on

        Returns
        -------
        Uses f as a ref to change its values
        adding 'action' and 'ports'
        """

        # action used when it's implied from a port in the name
        default_action = self.cf.get_ini_value_from_section('Rules', self.direction)

        # Evaluate rule:
        # 1. is this a rule we know about? If so use it
        # 2. Is this a numeric value then it's a port number
        # 3. Is this the name of a service in /etc/services?
        #    lookup portname in /etc/services and get port

        if self.rulesreader.exists(f['baseaction']):
            f['action'] = f['baseaction']
        elif f['baseaction'].isnumeric():
            f['action'] = default_action
            f['ports'] = f['baseaction']
        else:
            # may trigger an OSError exception
            f['ports'] = str(socket.getservbyname(f['baseaction']))
            f['action'] = default_action

    def validatecontents(self, f):
        """Check and validate optional contents

        Contents is a list of ip4, ip6 and domains

        Parameters
        ----------
        f : Dict[]
            Single record to work on

        Returns
        -------
        Uses f as a ref to change its values
        Create ip4 and ip6 entries in the record
        """

        # lists we are generating
        # use sets to remove duplicates
        ip = []
        ip6 = []

        # first split the contents into a list
        srclist = (v.strip() for v in f['contents'].split('\n') if v != '')

        # check the address
        # 1. check for ip4 using regex (can be a network with /)
        #    need ip format to allow for hostnames
        #    but re doesn't need to check for /
        # 2. if it has a ':' then it's ipv6
        # 3. otherwise it might be a hostname and
        #    we need to convert to a set of addresses
        # 4. ensure lists are sorted so that they remain
        #    in constant order
        ip4fmt = re.compile(r'(?:[0-9]{1,3}\.){3}[0-9]{1,3}')
        for possible in srclist:
            if ip4fmt.match(possible) is not None:
                norm = self.ipcheck('ip', possible, f['sourcefile'])
                if norm:
                    ip.append(norm)
            elif ':' in possible:
                norm = self.ipcheck('ip6', possible, f['sourcefile'])
                if norm:
                    ip6.append(norm)
            else:
                self.hostnamecheck(possible, ip, ip6, f['sourcefile'])

        # set up the output
        if any(ip):
            f['ip'] = sorted(list(set(ip)))
        if any(ip6):
            f['ip6'] = sorted(list(set(ip6)))


    # Function mapping for IP address checking
    addfn = {'ip':  ipaddress.IPv4Address,
             'ip6': ipaddress.IPv6Address}
    netfn = {'ip':  ipaddress.IPv4Network,
             'ip6': ipaddress.IPv6Network}

    def ipcheck(self, proto, p, srcfile):
        """ Check an proto address using ipaddress

        Parameters
        ----------
        proto : {'ip', 'ip6'}
            Protocol to use
        srcfile: str
            Action name used to show on error

        Returns
        -------
        str,None
            address if OK
            None if not
        """

        addfn = self.addfn[proto]
        netfn = self.netfn[proto]

        try:
            if '/' in p:
                i = netfn(p, strict=False)
            else:
                i = addfn(p)
            return str(i)
        except ipaddress.AddressValueError as e:
            log.error('%s: %s: %s', srcfile, p, str(e))
            return None

    @staticmethod
    def hostnamecheck(poss, ip, ip6, filename):
        """Evaluate possible host name

        and return any associated IP addresses

        Parameters
        ----------
        poss : str
            Possible hostname to check
        ip : List
            List of ip addresses
            Used as a ref to update list in caller
        ip6 : List
            List of ip6 addresses
            Used as a ref to update list in caller
        filename: str
            used in error message

        Returns
        -------
        Sets ip or ip6 to addresses found for the name
        """

        # NB will not return ipv6 if host is not configured for it
        try:
            res = socket.getaddrinfo(poss, None)
        except socket.gaierror:
            log.error("%s: %s hostname lookup failed", filename, poss)
            return

        # returns an array of addresses in a 5 tuple
        # (family, type, proto, canonname, sockaddr)
        # family is a constant
        # sockaddr is a tuple with element 0 being the address
        for family, iptype, proto, c, sockaddr in res: # pylint: disable=unused-variable
            if family == socket.AF_INET:
                ip.append(sockaddr[0])
            elif family == socket.AF_INET6:
                ip6.append(sockaddr[0])
