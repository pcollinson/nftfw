"""nftfw class to normalise IP addresses

Centralise ip checking in one place

Ignore allow local IPs
IPV6: make address into /112 (was /64 now controlled by
config value default_ipv6_mask)
is_white is address of fn to check if the ip is in the whitelist.
When present and returning true ignore the address

Uses cf.TESTING as a flag to allow ip addresses defined as local
to pass as OK

"""

import ipaddress
import logging
log = logging.getLogger('nftfw')

class NormaliseAddress:
    """ Put all IP checking into one class """

    def __init__(self, cf, error_name=""):
        """Set up cf, and a name for error reporting

        Parameters
        ----------
        cf : Config
        error_name : str
            Name used for error reporting
        """

        self.cf = cf
        self.error_name = ''
        if error_name != '':
            self.error_name = f'{error_name}:'

    # Functions for IP address checking
    addfn = {'ip':  ipaddress.IPv4Address,
             'ip6': ipaddress.IPv6Address}
    netfn = {'ip':  ipaddress.IPv4Network,
             'ip6': ipaddress.IPv6Network}
    ipname = {'ip': 'IPv4',
              'ip6':'IPv6'
              }

    def normal(self, ipstr, is_white=None):
        """Given a string - normalise and return a string

        Parameters
        ----------
        ipstr : str
            ip address to check

        is_white: function reference
        	is_white is address of fn to check if the
            ip is in the whitelist.

        Returns
        -------
        str
            return string or None if it should be ignored
        """

        proto = 'ip'
        if ':' in ipstr:
            proto = 'ip6'

        ipaddr = self.normal_ipaddr(proto, ipstr, is_white=is_white)
        return None if ipaddr is None else str(ipaddr)

    def normal_ipaddr(self, proto, ipstr, is_white=None):
        """Given a string - normalise and return a ipaddress

        Ignores local addresses

        Parameters
        ----------
        proto : {'ip', 'ip6'}
        ipstr : str
            ip address to check
        is_white: function reference to is_white in
            whitelistcheck.py - if wanted
            Checks of the ipaddress is in the whitelist

        Returns
        -------
        str
            return string or None if it should be ignored
        """

        if hasattr(self.cf, 'TESTING'):
            return self._normal_ipaddr_test(proto, ipstr, is_white)
        return self._normal_ipaddr_prod(proto, ipstr, is_white)

    def _normal_ipaddr_prod(self, proto, ipstr, is_white=None):
        """ Production version, ignores non global addresses"""

        ipaddr = self.make_ipaddr(proto, ipstr)
        if ipaddr is None:
            return None
        if ipaddr.is_global:
            if is_white is not None \
               and is_white(proto, ipaddr):
                log.info('%s Whitelisted address %s ignored', self.error_name, ipaddr)
                return None
            # falls out
        else:
            log.info('%s Local address %s ignored', self.error_name, ipaddr)
            return None

        return ipaddr

    def _normal_ipaddr_test(self, proto, ipstr, is_white=None):
        """ Testing version to allow local addresses to be used for testing """

        ipaddr = self.make_ipaddr(proto, ipstr)
        if ipaddr is None:
            return None
        if is_white is not None \
           and is_white(proto, ipaddr):
            log.info('%s Whitelisted address %s ignored', self.error_name, ipaddr)
            return None

        return ipaddr


    def make_ipaddr(self, proto, ipstr):
        """Given a string, proto (ip|ip6) create an ipaddress object

        All IPv6 addresses are made into /112 networks
        controlled by default_ipv6_mask in config

        Parameters
        ----------
        proto : {'ip', 'ip6'}
        ipstr : str
            ip address to check

        Returns
        -------
        ipaddress : object of appropriate type
        """

        addfn = self.addfn[proto]
        netfn = self.netfn[proto]
        ipname = self.ipname[proto]

        try:
            if '/' in ipstr:
                ipaddr = netfn(ipstr, strict=False)
            else:
                ipaddr = addfn(ipstr)
                if proto == 'ip6':
                    ipaddr = netfn((ipaddr, self.cf.default_ipv6_mask),
                                   strict=False)
        except ValueError as e:
            log.error('%s Problem converting %s address %s - %s',
                      self.error_name, ipname, ipstr, str(e))
            return None
        return ipaddr

    def is_network(self, proto, ipaddr):
        """Is the ipaddr a network

        Parameters
        ----------
        proto : {'ip', 'ip6'}
        ipaddr : ipaddress object
            address to check
        """

        return isinstance(ipaddr, (self.netfn[proto],))
