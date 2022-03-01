""" nftfwedit - Print IP address information
"""

from socket import gethostbyaddr, herror, getservbyport
from .nftfwls import datefmt
from .stats import duration, frequency
from .nf_edit_validate import validate_and_return_ip
from .fwdb import FwDb
from .geoipcountry import GeoIPCountry
from .dnsbl import Dnsbl

class PrintInfo:
    """ Class to print ip addresses """

    def __init__(self, cf):
        """Initialise

        Parameters
        ----------
        cf : Config
        """

        self.cf = cf
        # open and retain classes we may use
        self.db = FwDb(cf, createdb=False)
        self.geoip = GeoIPCountry()
        self.dnsbl = Dnsbl(cf)

    def check_online(self, ipstr):
        """See if the ip is in the blacklist dir

        Parameters
        ----------
        ipstr : str
            ip to check

        Returns
        -------
        str : path to file
              or None
        """

        blacklistpath = self.cf.etcpath('blacklist')
        if '/' in ipstr:
            ipstr = ipstr.replace('/', '|')
        filepath = blacklistpath / ipstr
        if filepath.exists():
            return str(filepath.name)
        auto = ipstr + '.auto'
        filepath = blacklistpath / auto
        if filepath.exists():
            return str(filepath.name)
        return None

    def print_ip(self, ipaddress, showhostinfo=False):
        """Print information about the IP address

        Parameters
        ----------
        ipaddress : str
            ip to print
        """

        ipstr = validate_and_return_ip(ipaddress)
        if ipstr is None:
            return

        fmt = '%-10s %s'
        print(fmt % ('IP:', str(ipstr)))

        # gethostbyaddr information
        if showhostinfo:
            self.print_hostinfo(fmt, ipstr)

        online = self.check_online(ipstr)
        if online is not None:
            print(fmt % ('Active:', f'Blacklisted as {online}'))
        else:
            print(fmt % ('Active:', 'No'))

        # lookup in database
        lookup = self.db.lookup_by_ip(ipstr)
        if not any(lookup):
            print(fmt % ('Database:', 'Not found in database'))
        else:
            self.format_item(fmt, lookup[0])


        # GeoIP2 information
        if self.geoip.isinstalled():
            country, iso = self.geoip.lookup(ipstr)
            if country is not None:
                print(fmt % ('Country:', f'{country} ({iso})'))

        # DNSBL information
        if self.dnsbl.isinstalled():
            lookup = self.dnsbl.lookup(ipstr)
            if any(lookup):
                for name, inlist, verbose in lookup:
                    if inlist:
                        print(fmt % (name.capitalize()+':', verbose))

    @staticmethod
    def print_hostinfo(fmt, ipstr):
        """ Print hostinfo """

        try:
            host, alias, ips = gethostbyaddr(str(ipstr))
            if host is not None:
                print(fmt % ('Hostname:', host))
            if any(alias):
                print(fmt % ('Alias:', ', '.join(alias)))
            if any(ips):
                rem = [i for i in ips if i != ipstr]
                if any(rem):
                    print(fmt % ('Other IPs:', ', '.join(rem)))
        except herror:
            print(fmt % ('Hostname:', 'Unknown'))

    def format_item(self, fmt, current):
        """Format standard values from a record

        Parameters
        ----------
        fmt : str
            format for output
        current : database record
        """

        cf = self.cf

        print(fmt % ('Pattern:', current['pattern']))
        portlist = self.ports_by_name(current['ports'])
        print(fmt % ('Ports:', portlist))
        if current['useall']:
            print(fmt % ('', "Forced to 'all' in firewall"))
        print(fmt % ("Latest:", datefmt(cf.date_fmt, current['last'])))
        print(fmt % ("First:", datefmt(cf.date_fmt, current['first'])))
        first = current['first']
        last = current['last']
        if first < last:
            print(fmt % ("Duration:", duration(first, last)))
        print(fmt % ("Matches:", self.format_freq(first, last, current['matchcount'])))
        print(fmt % ("Incidents:", self.format_freq(first, last, current['incidents'])))

    @staticmethod
    def ports_by_name(ports):
        """ Turn comma separated port list into list with
        service names
        """

        if ports == 'all':
            return ports
        out = []
        plist = ports.split(',')
        for pno in plist:
            portno = pno.strip()
            try:
                serv = getservbyport(int(portno))
                out.append(serv)
            except OSError:
                out.append(portno)
        return ", ".join(out)

    @staticmethod
    def format_freq(first, last, val):
        """Format a value with a frequency

        Parameters
        ----------
        first : int
            First timestamp
        last : int
            Last timestamp
        val : int
            Value of item to be displayed
        """

        freq = ''
        if first < last \
           and val > 1:
            freq = frequency(first, last, val)
            if freq != '':
                freq = ' - ' + freq
        return str(val) + freq
