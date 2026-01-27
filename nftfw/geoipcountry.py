"""GeoIP2 support for nftfw - Country lookup for IP addresses.

This module provides optional GeoIP2 integration for looking up the country
associated with an IP address. It gracefully handles the absence of GeoIP2
libraries, allowing nftfw to run without requiring GeoIP2 as a dependency.

**Requirements:**

To use this module, install the following packages:
    - python3-geoip2: Python library for MaxMind GeoIP2 databases
    - geoipupdate: Tool to download and update GeoIP2 databases
    - MaxMind GeoLite2 license: Free license from MaxMind (registration required)

**Database Location:**

The module expects the GeoLite2 Country database at:
    /var/lib/GeoIP/GeoLite2-Country.mmdb

**Setup Instructions:**

1. Register for a free MaxMind GeoLite2 account:
   https://dev.maxmind.com/geoip/geoip2/geolite2/

2. Install required packages::

       apt-get install python3-geoip2 geoipupdate

3. Configure geoipupdate with your MaxMind account credentials
4. Run geoipupdate to download the database

**Graceful Degradation:**

If GeoIP2 libraries are not installed or the database file is missing, the module
will still load successfully but isinstalled() will return False and lookup()
will return (None, None).

**Related Modules:**
    - nftfwls: Uses GeoIPCountry to display country information for blacklisted IPs
    - nftnetchk: Uses GeoIPCountry to show country data for network addresses

Example:
    Check if GeoIP2 is available and look up an IP address::

        geo = GeoIPCountry()
        if geo.isinstalled():
            name, iso = geo.lookup("8.8.8.8")
            if name:
                print(f"{name} ({iso})")  # United States (US)
        else:
            print("GeoIP2 not available")

    Handle IP addresses with CIDR notation::

        name, iso = geo.lookup("8.8.8.8/24")  # Mask is automatically stripped
"""
from __future__ import annotations

import os.path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from geoip2.database import Reader  # type: ignore[import]
    from geoip2.errors import (  # type: ignore[import]
        AddressNotFoundError as AddressNotFoundErrorType
    )
    from maxminddb import InvalidDatabaseError as InvalidDatabaseErrorType

class GeoIPCountry:
    """Look up IP addresses in GeoIP2 database to determine country.

    This class provides a wrapper around the MaxMind GeoIP2 library for country
    lookups. It handles optional GeoIP2 installation gracefully, allowing the
    class to be instantiated even when GeoIP2 is not available.

    **Attributes:**
        countryreader: GeoIP2 Reader instance if available, None otherwise
        country: Path to the GeoLite2 Country database file
        AddressNotFoundError: Exception class for IP addresses not in database
        InvalidDatabaseError: Exception class for database corruption/format errors

    **Initialization:**

    On initialization, the class attempts to import GeoIP2 libraries and open
    the country database. If either step fails, the class remains functional
    but isinstalled() returns False and lookup() returns (None, None).

    **Thread Safety:**

    The GeoIP2 Reader is thread-safe for lookups after initialization.

    Example:
        Basic usage with availability check::

            geo = GeoIPCountry()
            if not geo.isinstalled():
                print("GeoIP2 not available")
            else:
                name, iso = geo.lookup("1.1.1.1")
                print(f"Country: {name} ({iso})")

        Multiple lookups::

            geo = GeoIPCountry()
            ips = ["8.8.8.8", "1.1.1.1", "208.67.222.222"]
            for ip in ips:
                name, iso = geo.lookup(ip)
                if name:
                    print(f"{ip}: {name} ({iso})")
    """

    # Set up reader
    countryreader: Reader | None = None

    # Country database
    country: str = '/var/lib/GeoIP/GeoLite2-Country.mmdb'

    # Errors
    # pylint: disable=invalid-name
    AddressNotFoundError: type[AddressNotFoundErrorType] | None = None
    InvalidDatabaseError: type[InvalidDatabaseErrorType] | None = None

    def __init__(self) -> None:
        """Initialise GeoIPCountry and attempt to load GeoIP2 database.

        Attempts to import GeoIP2 libraries and open the country database file.
        If GeoIP2 is not installed or the database file is missing, initialization
        succeeds but countryreader remains None.

        **Import Handling:**

        Uses dynamic imports to handle optional GeoIP2 dependency. If ImportError
        occurs, the exception is silently caught and the class remains usable but
        non-functional (all lookups return None).

        **Database Loading:**

        If the country database file exists at the expected path, opens a Reader
        for that database. The Reader remains open for the lifetime of the instance.

        Returns:
            None

        Example:
            Standard initialization::

                geo = GeoIPCountry()
                # Check if initialization succeeded
                if geo.isinstalled():
                    print("GeoIP2 ready for lookups")
        """

        # geoip2 may not be installed
        # but pylint will complain on bullseye and later with import-outside-toplevel
        # if the disable code is installed, pylint will complain on buster
        # about the disable code below (now deactivated)
        # pylint: disable=import-outside-toplevel

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
            pass  # GeoIP2 not installed, countryreader remains None

    def isinstalled(self) -> bool:
        """Check if GeoIP2 is available and ready for lookups.

        Returns True if the GeoIP2 library was successfully imported and the
        country database file was successfully opened. Returns False if either
        the library is not installed or the database file is missing/corrupt.

        Returns:
            True if GeoIP2 is available and functional, False otherwise.

        Example:
            Check before performing lookups::

                geo = GeoIPCountry()
                if geo.isinstalled():
                    # Safe to call lookup()
                    name, iso = geo.lookup("8.8.8.8")
                else:
                    print("Install python3-geoip2 and geoipupdate")
        """
        return self.countryreader is not None

    def lookup(self, ip: str) -> tuple[str | None, str | None]:
        """Look up an IP address in the GeoIP2 database to get country information.

        Performs a country lookup for the given IP address. Automatically strips
        CIDR notation if present (e.g., "1.1.1.1/24" becomes "1.1.1.1"). Returns
        both the full country name and the two-character ISO country code.

        **Return Values:**

        Returns (None, None) in the following cases:
            - GeoIP2 is not installed (countryreader is None)
            - IP address is not found in the database
            - IP address format is invalid
            - Database error occurs

        Returns (name, iso) where:
            - name: Full country name (e.g., "United States")
            - iso: Two-character ISO code (e.g., "US")

        **CIDR Notation Handling:**

        If the IP address includes CIDR notation (/24, /28, /32, etc.), the mask
        is automatically stripped before lookup. Supports masks from /0 to /999
        (though only /0-/32 for IPv4 and /0-/128 for IPv6 are valid).

        Args:
            ip: IP address string, optionally with CIDR notation (e.g., "8.8.8.8"
                or "8.8.8.8/24")

        Returns:
            Tuple of (country_name, iso_code). Both are None if lookup fails or
            GeoIP2 is not available. Either may be None individually if the
            database has incomplete information for that IP.

        Example:
            Basic lookup::

                geo = GeoIPCountry()
                name, iso = geo.lookup("8.8.8.8")
                if name:
                    print(f"Google DNS is in {name} ({iso})")
                # Output: Google DNS is in United States (US)

            Handle CIDR notation::

                name, iso = geo.lookup("1.1.1.0/24")
                # Mask is stripped, looks up 1.1.1.0

            Handle missing data gracefully::

                name, iso = geo.lookup("192.168.1.1")
                if not name:
                    print("IP not found or private address")
        """

        # pylint: disable=no-member

        if self.countryreader is None:
            return None, None

        # remove any mask from ip
        if ip[-4] == '/':
            ip = ip[0:-4]
        elif ip[-3] == '/':
            ip = ip[0:-3]
        elif ip[-2] == '/':
            ip = ip[0:-2]

        try:
            cn = self.countryreader.country(ip)
            iso: str | None = None
            cname: str | None = None
            if cn.country.iso_code:
                iso = cn.country.iso_code
            if cn.country.name:
                cname = cn.country.name
            return cname, iso
        except (ValueError, AttributeError,  # type: ignore[misc]
                self.AddressNotFoundError, self.InvalidDatabaseError):
            return None, None
