""" nftfw - Geoip2 support

Requires python3-geoip2 and geoupupdate packages
and a license from MaxMind
https://dev.maxmind.com/geoip/geoip2/geolite2/

"""
import os.path

class GeoIPCountry:
    """Lookup ip addresses in geoip2 """

    # Set up reader
    countryreader = None

    # Country database
    country = '/var/lib/GeoIP/GeoLite2-Country.mmdb'

    def __init__(self):
        """Check geoip2 availability

        See if the country database file can be found
        """
        try:
            from geoip2.database import Reader
            if os.path.exists(self.country):
                self.countryreader = Reader(self.country)
        except ImportError:
            return

    def isinstalled(self):
        """Return True if we have a reader """

        return self.countryreader is not None

    def lookup(self, ip):
        """Lookup an ip in the geoip2 database

        Parameters
        ----------
        ip : str
            Ip to lookup

        Returns
        -------
        tuple (name, iso)
        name : str
            Country name
            None if no reader
            or no result
        iso : str
            Two character ISO code for the country
        """

        # pylint: disable=no-member

        if self.countryreader is None:
            return(None, None)

        # remove any mask from ip
        if ip[-3] == '/':
            ip = ip[0:-3]
        elif ip[-2] == '/':
            ip = ip[0:-2]

        try:
            cn = self.countryreader.country(ip)
            iso = None
            cname = None
            if cn.country.iso_code:
                iso = cn.country.iso_code
            if cn.country.names['en']:
                cname = cn.country.names['en']
            return(cname, iso)
        except ValueError:
            return(None, None)
