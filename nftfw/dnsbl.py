"""Lookup ip addresses in DNS Blacklists for nftfwedit -p

Blacklists and their lookup domains are in config.ini
Beware Spamhaus lookups will not work with some public DNS servers
that offer public resolvers. They will return an error value and not
NXDOMAIN.

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
        self.lists = {}

        # match codes from DNSBLs
        self.default_match = ('127.0.0.2', )
        # Zen values
        self.special_match = {'spamhaus': ('127.0.0.2', '127.0.0.3', '127.0.0.4', '127.0.0.9', '127.0.0.10', '127.0.0.11'),}
        self.match_values = self.default_match

        # get possible lookups
        #self.lists = {k:v for k, v in cf.parser['Nftfwedit'].items()}
        for k, v in cf.parser['Nftfwedit'].items():
            self.lists[k.lower()] = v

        try:
            # Import here because the module may not be installed on the system
            # but pylint will complain on bullseye with import-outside-toplevel
            # if the disable code is installed, pylint will complain on buster
            # about the disable code below (now deactivated)
            import dns.resolver
            self.resolver = dns.resolver.Resolver()
            self.NXDOMAIN = dns.resolver.NXDOMAIN
        except ImportError:
            self.lists = {}
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
            (status, verbose) = self.dnslookup(name, domain, my_ip)
            app = (name, status, verbose)
            result.append(app)
        return result

    def dnslookup(self, name, domain, my_ip):
        """Lookup single ip in blacklist

        Parameters
        ----------
        name : str
            Lower case DNSBL name
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
            return False, ""
        query = ma.group(1) + domain

        # set up found result set
        match_value = self.default_match
        if name in self.special_match:
            match_value = self.special_match[name]

        try:
            #perform a record lookup. A failure will trigger the NXDOMAIN exception
            answers = self.resolver.query(query, "A")
            #No exception was triggered, IP is listed in bl.
            # Check we have a valid value
            if len(answers) == 1 and \
               answers[0].address not in match_value:
                return False, f'{my_ip} lookup fail for {domain}'

            #Now get TXT record
            answer_txt = self.resolver.query(query, "TXT")
            result = f'{my_ip} in {domain} ({answers[0]}: {answer_txt[0]})'
            return True, result
        except self.NXDOMAIN:
            return False, f'{my_ip} not in {domain}'
        except: # pylint: disable=bare-except
            return False, sys.exc_info()[0]
