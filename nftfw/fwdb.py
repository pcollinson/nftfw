"""nftfw sqlite3 database management for firewall table

NB The database schema used by nftfw differs from Symbiosis, and
is not compatible

Database schema
---------------
ip : str
    value of IP that matched the rules
    primary key - constrained to be unique
pattern : str
    source pattern for match, will become a
    comma separated list when different patterns
    match the same IP
incidents : int
    Number of incidents for this IP. Tthe count will be
    1 of one set of matches in the same blacklist run
    will also be bumped by feedback from scans tagged
    as feedback.
matchcount : int
    number of matches found in logs
    used as criteria for banning
first : int
    Unixtime of first incident
last : int
    Unixtime of last incident
ports : str
    Comma separated list of ports matched
    is extended if more than one pattern is matched
useall : bool
    boolean to indicate that all ports should be used
    in firewall rules (Value can be True or False)
    This means that the ports that were originally set can be
    retained
multiple : bool
    Unused
isdnsbl : bool
    boolean this ip found in some dns blacklist database
    Currently unused
"""

import logging
from sqdb import SqDb
log = logging.getLogger('nftfw')

class FwDb(SqDb):
    """Manages the firewall information database

    Superclass: SqDb for sqlite3 API
    """

    def __init__(self, cf, createdb=True):
        """ Provides table name and create statement

        Parameters
        ----------
        cf : Config
        createdb : bool
            Create database control, if False
            assume database exists
        """

        create = """CREATE TABLE blacklist
                    (ip TEXT UNIQUE PRIMARY KEY, pattern TEXT,
                    incidents INT, matchcount INT,
                    first INT, last INT, ports TEXT,
                    useall INT, multiple INT,
                    isdnsbl INT);
                    CREATE UNIQUE INDEX blacklist_ix ON blacklist(ip);
             """
        path = cf.varfilepath('firewall')
        if createdb:
            super().__init__(cf, path, {'blacklist':create})
        else:
            super().__init__(cf, path, None)

    def lookup_by_ip(self, ip):
        """Lookup an ip in the table and return match

        should only be one

        Parameters
        ----------
        ip : str
            IP address to lookup

        Returns
        -------
        List[Dict[database schema]]
        or
        []
        """

        return self.lookup('blacklist', key='ip', val=ip)

    def lookup_ips_for_deletion(self, before):
        """Lookup the ips suitable for deletion before timestamp

        Parameters
        ----------
        before : int
            Timestamp to use as a reference


        Returns
        -------
        List[Dict[
            ip: str
               IP address
            ]]
        or [] if none
        """

        return self.lookup('blacklist',
                           what='ip',
                           key='last',
                           predicate='<',
                           val=before)

    def insert_ip(self, argdict):
        """Insert args into the table

        Parameters
        ----------
        argdict : Dict[values to be set]
            Should be complete record
        """

        self.insert('blacklist', argdict)

    def update_ip(self, argdict, ip):
        """Update the table for the ip

        Parameters
        ----------
        argdict : Dict[values to be set]
            Will only update values in the dict
        ip : str
            IP to update
        """

        self.update('blacklist', argdict, 'ip', ip)


    def delete_ip(self, ip):
        """Delete ip from database

        Parameters
        ----------
        ip : str
            IP to delete

        Returns
        -------
        int
            Number of deletions
        """

        deleted = self.delete('blacklist', 'ip', '=', ip)
        return deleted

    def clean(self, lasttime):
        """Clean database

        Delete items from the database where
        last is less than lasttime

        Parameters
        ----------
        lasttime : int
            Timestamp of deletion threshold

        Returns
        -------
        int
            Number of deletions
        """

        deleted = self.delete('blacklist', 'last', '<', lasttime)
        if deleted is not None \
           and deleted != 0:
            self.vacuum()
        return deleted

    def clean_not_in(self, lasttime, not_in_list):
        """Clean database leaving ips in list

        If anything changes, use VACUUM on the database

        Parameters
        ----------
        lasttime : int
            Timestamp of deletion threshold
        not_in_list: List[str]
            List of ips not to delete

        Returns
        -------
        int
            Number of deletions
        """

        deleted = self.delete_not_in('blacklist',
                                     'last', '<', lasttime,
                                     'ip', not_in_list)
        if deleted is not None \
           and deleted != 0:
            self.vacuum()
        return deleted
