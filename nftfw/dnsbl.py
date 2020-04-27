"""Lookup ip addresses in DNS Blacklists for nftfwedit -p

Blacklists and their lookup domains are in config.ini

[Nftfwedit]
# Supply DNSBL lookup names and lookup addresses
# None set in default settings
# These are possible examples
;SpamHaus=zen.spamhaus.org
;Barracuda=b.barracudacentral.org
;SpamCop=bl.spamcop.net

Needs python3-dnspython

"""

import sys
import ipaddress
import re

class Dnsbl:
    """Lookup IP addresses in DNS Blacklists"""

    #pylint: disable=invalid-name
    # complaint about cf and NXDOMAIN

    def __init__(self, cf):
        """Dnsbl init

        Parameters
        ----------
        cf : Config
        """

        self.cf = cf
        self.lists = []

        # get possible lookups
        self.lists = {k:v for k, v in cf.parser['Nftfwedit'].items()}

        try:
            import dns.resolver
            self.resolver = dns.resolver.Resolver()
            self.NXDOMAIN = dns.resolver.NXDOMAIN
        except ImportError:
            self.lists = []
            print("Installation of python3-dnspython is required, run:")
            print("sudo apt install python3-dnspython")
            print("It's also recommended to run a caching nameserver")

    def isinstalled(self):
        """Check if there are any installed lists

        Returns
        -------
        bool
            True if any lookups from the ini file
        """

        return any(self.lists)

    def lookup(self, my_ip):
        """Lookup the IP in the DNS using lists

        Parameters
        ----------
        my_ip : str
            IP to lookup

        Returns
        -------
        list of tuples
            0: str
                name of blacklist
            1: bool
                false if no result
            2: str
                Message from DNSBL
        """

        result = []
        # in case use has supplied form in blacklist.d
        my_ip = my_ip.replace('|', '/')

        for name, domain in self.lists.items():
            (status, verbose) = self.dnslookup(domain, my_ip)
            app = (name, status, verbose)
            result.append(app)
        return result

    def dnslookup(self, domain, my_ip):
        """Lookup single ip in blacklist

        Parameters
        ----------
        domain : str
            Domain used for lookup
        my_ip : str
            IP to lookup

        Returns
        -------
        tuple
            0 : bool
                True if lookup succeeds
            1 : str
                Result from DNSBL if true
                Error if lookup failed
                Empty if domain lookup failed
        """

        # first mess with ip
        if '/' in my_ip:
            ip = ipaddress.ip_network(my_ip, strict=False)
            ip = ip.network_address
        else:
            ip = ipaddress.ip_address(my_ip)
        reverse = ip.reverse_pointer
        ma = re.match('^(.*)(in-addr.arpa|ip6.arpa)$', reverse)
        if ma is None:
            return (False, "")
        query = ma.group(1) + domain
        try:
            #perform a record lookup. A failure will trigger the NXDOMAIN exception
            answers = self.resolver.query(query, "A")
            #No exception was triggered, IP is listed in bl. Now get TXT record
            answer_txt = self.resolver.query(query, "TXT")
            result = f'{my_ip} in {domain} ({answers[0]}: {answer_txt[0]})'
            return (True, result)
        except self.NXDOMAIN:
            return (False, f'{my_ip} not in {domain}')
        except: # pylint: disable=bare-except
            return (False, sys.exc_info()[0])
