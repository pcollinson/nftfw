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

    # Errors
    # pylint: disable=invalid-name
    AddressNotFoundError = None
    InvalidDatabaseError = None

    def __init__(self):
        """Check geoip2 availability

        See if the country database file can be found
        """

        # All this is to allow the system to run when geoip2 is not installed
        # so we don't insist on it
        try:
            from geoip2.database import Reader
            from geoip2.errors import AddressNotFoundError
            from maxminddb import InvalidDatabaseError
            self.AddressNotFoundError = AddressNotFoundError
            self.InvalidDatabaseError = InvalidDatabaseError

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
            if cn.country.name:
                cname = cn.country.name
            return(cname, iso)
        except (ValueError, AttributeError, self.AddressNotFoundError, self.InvalidDatabaseError):
            return(None, None)
