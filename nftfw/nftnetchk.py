#!/usr/bin/python3
"""
Program to look at the contents of the nftfw firewall.db database
and see if these addresses can be removed because they are being
rejected by entries in the blacknets.d directory.
"""

import sys
import logging
import ipaddress
import datetime
import argparse
from prettytable import PrettyTable
from .config import Config
from .netreader import NetReaderFromFiles
from .fwdb import FwDb
from .stats import duration
log = logging.getLogger('nftfw')

class NetsCheck:
    """ Check ips in the firewall database against
    the content of the blacknets.d files
    """

    def __init__(self, cf, justlist):

        self.cf = cf
        self.justlist = justlist
        # defined in get_blacknets
        self.nets = None
        self.source = None
        # defined in get_ips_from_db
        self.iplist = []
        self.timedata = []

    def get_blacknets(self):
        """ Use the netreader contents """

        netr = NetReaderFromFiles(self.cf, 'blacknets')

        # self.nets is a hash with keys
        # ip and ip6
        # each values are hashes with
        # keys of the footprint value
        # and an argument of an IP4 or
        # IP6 network object
        self.nets = netr.nets

        # self.source is a hash that
        # maps the filename to a list of
        # footprint values in the file
        try:
            getattr(netr, 'source')
            self.source = netr.source
        except AttributeError:
            print("Sorry, the version of 'netreader' doesn't have support for this script")
            print("You need version at least v0.9.20 of nftfw")
            sys.exit(1)

    def get_ips_from_db(self):
        """ Get all the IPs from the database

        return list of approprate network objects
        """

        db = FwDb(self.cf, createdb=False)
        results = db.lookup('blacklist', what="ip,first,last", orderby='last DESC')
        db.close()

        # results is a list of hash 'ip', 'first' and 'last' values
        iplist = [elem['ip'] for elem in results]
        ips = [ipaddress.ip_address(ip)
               for ip in iplist if '/' not in ip]
        ipn = [ipaddress.ip_network(ip, strict=False)
               for ip in iplist if '/' in ip]
        self.iplist = ips + ipn

        # Make a hash indexed by ip
        # to print times on the output
        self.timedata = {elem['ip']: elem for elem in results}

    def search_for_ip_match(self, ipcheck):
        """ Search for ipcheck in self.nets
        return the footprint value on a match
        there may be more than one match

        returns list of pairs
        (footprint, matched ip value)
        """

        out = []
        ipproto = 'ip'
        if ipcheck.version == 6:
            ipproto = 'ip6'
        # select appropriate set of values
        srchfor = self.nets[ipproto]
        if srchfor:
            # srch is list of hashes: {footprint: ipobject}
            for footprint, ipobj in srchfor.items():
                if ipcheck in ipobj:
                    out.append([footprint, ipobj])
        return out

    def footprint_search(self, footp):
        """ Look for footprint in file list

        return list of filenames
        """
        out = []
        for fname,footplist in self.source.items():
            if footp in footplist:
                out.append(fname)
        return out

    @staticmethod
    def datefmt(fmt, timeint):
        """Return formatted date - here so it can be changed
        in one place

        Parameters
        ----------
        fmt : str
            Time format from the ini file
        timeint : int
            Unix timestamp

        Returns
        -------
        str
            Formatted string
        """

        value = datetime.datetime.fromtimestamp(timeint)
        return value.strftime(fmt)

    def process(self):
        """ Sequence all the work """

        # We need the date format
        date_fmt = self.cf.get_ini_value_from_section('Nftfwls', 'date_fmt')
        # get blacknet data
        self.get_blacknets()
        # get ips from the database
        self.get_ips_from_db()

        if not self.justlist:
            pt = PrettyTable()
            pt.field_names = ['IP', 'Found in', 'Net',
                              'Latest', 'First', "Duration"]

        haveptoutput = False
        for ipobj in self.iplist:
            matchlist = self.search_for_ip_match(ipobj)
            for footprint,ipmatched in matchlist:
                filenames = self.footprint_search(footprint)
                for filename in filenames:
                    if self.justlist:
                        print(f'{str(ipobj)}')
                    else:
                        haveptoutput = True
                        ip = str(ipobj)
                        firstst = self.datefmt(date_fmt, self.timedata[ip]['first'])
                        lastst  = self.datefmt(date_fmt, self.timedata[ip]['last'])
                        if firstst == lastst:
                            firstst = '-'
                            dur = '-'
                        else:
                            dur = duration(self.timedata[ip]['first'], self.timedata[ip]['last'])
                        pt.add_row([ip, filename, ipmatched, lastst, firstst, dur])

        if haveptoutput and not self.justlist:
            # set up format
            pt.align = 'l'
            print(pt)

def main():
    """ Main code """

    cf = Config(dosetup=False)

    # Get the ini file setup
    # with no sys logging
    # and a private log format
    try:
        cf.readini()
    except AssertionError as e:
        print(f'Aborted: {str(e)}')
        sys.exit(1)
    # turn off logsyslog
    cf.set_logger(logsyslog=False)
    cf.set_ini_value_with_section('Logging', 'logfmt', 'Error: %(message)s')
    try:
        cf.setup()
    except AssertionError as e:
        log.critical('Aborted: Configuration problem: %s', str(e))
        sys.exit(1)

    ap = argparse.ArgumentParser(prog='are_ips_in_nets')
    ap.add_argument('-l', '--list',
                    help='List the just ips that can be deleted',
                    action='store_true')

    args = ap.parse_args()
    ck = NetsCheck(cf, args.list)
    ck.process()
    sys.exit(0)

if __name__ == '__main__':

    main()
    sys.exit(0)
