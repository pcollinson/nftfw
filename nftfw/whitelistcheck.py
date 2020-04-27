"""nftfw WhiteListCheck class

Checks for IPs in the whitelist
Read whitelist contents from whitelist.d
creates a lookup dictionary
Used in blacklist.py

Offers is_white method to see if it's there

"""
import logging
from listreader import ListReader
from normaliseaddress import NormaliseAddress
log = logging.getLogger('nftfw')

class WhiteListCheck:
    """ Check for IPs in whitelist """

    # pylint: disable=too-few-public-methods

    def __init__(self, cf):
        """ Read whitelist contents from whitelist.d

        Create whitedict - dict indexed by ip|ip6
        values are ipaddress classes

        """

        self.cf = cf
        wf = ListReader(cf, 'whitelist', need_compiled_ix=False)
        whitelist = wf.srcdict.keys()

        self.whitedict = {'ip':[], 'ip6':[]}
        # speed up lookups
        self.havenets = {'ip':False, 'ip6':False}

        # used as a hook from blacklist.py
        # to avoid starting a new instance
        self.normalise_addr = NormaliseAddress(cf, error_name='Blacklist')

        for ipstr in whitelist:
            proto = 'ip'
            if ':' in ipstr:
                proto = 'ip6'
            ipa = self.normalise_addr.normal_ipaddr(proto, ipstr)
            if ipa is not None \
               and ipa not in self.whitedict[proto]:
                self.whitedict[proto].append(ipa)
                if self.normalise_addr.is_network(proto, ipa):
                    self.havenets[proto] = True

    def is_white(self, proto, ipaddr):
        """ Lookup ipaddr in white list dict

        Parameters
        ----------
        proto : {'ip', 'ip6'}
        ipadddr : str
            ipaddress object to check

        Returns
        -------
        bool
             Return True if is in whitelist
            False otherwise
        """

        if not any(self.whitedict[proto]):
            return False

        # most common case
        if ipaddr in self.whitedict[proto]:
            return True

        # exit if no networks for this protocol
        if not self.havenets[proto]:
            return False

        # check for subnets
        ipaddr_is_network = self.normalise_addr.is_network(proto, ipaddr)

        # if the stored value is a net
        # return True if ipaddr a subnet of it
        # or if ipaddr is part of the net
        for k in self.whitedict[proto]:
            if self.normalise_addr.is_network(proto, k):
                if ipaddr_is_network:
                    if ipaddr.subnet_of(k):
                        return True
                elif ipaddr in k:
                    return True
        return False
