""" Generate the installation instructions for one of
blacklist.d and whitelist.d.

Reads the setup from Sympl/Symbiosis and prints actions that will be taken
Much of this abstracted from nftfw listreader.py

"""
import sys
import re
import ipaddress
from prettytable import PrettyTable
from fwdb import FwDb
from configerr import ConfigError

class ProcessLists:
    """Process a single directory to create installation instructions for
    blacklist.d and whitelist.d.

    The records array contains dictionaries with the following fields:

    sourcepath:     Path of original file
    nftfwaction:    For compatibility with the install code
                    can be set to 'ignore'
    contents:       Contents of file
    stat:           Stat of original file
    outname:        Name of output file (again for compat with install)
    ---- Local list values
    ip:             Ip address we are dealing with
    is_auto:        Is an .auto file
    in_nftfwdb      True/False
    """

    # pylint: disable=redefined-outer-name,invalid-name

    def __init__(self, cf, dirstem):
        """Called with the config class and a directory key to process """

        self.cf = cf
        srcpath = cf.paths['src'][dirstem]

        self.is_disabled = False
        disabled = srcpath / 'disabled'
        self.is_disabled = disabled.exists()

        self.is_blacklist = False
        if dirstem == 'blacklist':
            self.is_blacklist = True
            # does the firewall database exist?
            self.have_firewall_db = cf.nftfw_firewall_path.exists()

        # re matches
        # sequence of 0-9a-f . or : as far as it can
        #     captured in match[1]
        # followed optionally by | and one or two digits
        #     captured in match[2]
        # followed optionally by .auto
        strict = re.compile(r'([0-9a-f.:]*?)(\|[0-9]{1,2})?(\.auto)?$', re.I)
        # Generate a list of dicts
        self.records = []
        for p in sorted(srcpath.glob('[0-9a-z]*')):
            new = {}
            ma = strict.match(p.name)
            if ma is not None and p.is_file():
                new['sourcepath'] = p
                new['srcname'] = p.name
                new['outname'] = p.name
                new['ip'] = ma.group(1)
                if ma.group(2) is not None:
                    new['ip'] = new['ip'] + '/' + ma.group(2)[1:]
                new['contents'] = p.read_text()
                # get stat to give a date for the database
                new['stat'] = p.stat()
                new['is_auto'] = ma.group(3) is not None
                # set ignore action if ip doesn't check ou
                new['nftfwaction'] = True \
                    if self.validateip(new['ip']) \
                       else 'ignore'
                # set database lookup flag off
                new['in_nftfwdb'] = None
                self.records.append(new)
        if dirstem == 'blacklist':
            self.de_duplicate()
            self.lookupindb()


    @staticmethod
    def validateip(ip):
        """Validate the ipaddress

        Parameters
        ----------
        ip: str

        Returns
        -------
        True if OK, false otherwise
        """
        try:
            if '/' in ip:
                ipaddress.ip_network(ip, strict=False)
            else:
                ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
        return True

    def de_duplicate(self):
        """ It's possible to have a file called 'ip'
        and an automatically generated one of 'ip.auto'

        This chooses the auto one, and will mark the other
        as a 'duplicate'.
        """

        for ix in range(len(self.records)-1):
            if self.cf.skiprecord(self.records[ix]):
                continue
            for jx in range(ix+1, len(self.records)):
                if self.cf.skiprecord(self.records[jx]):
                    continue
                if self.records[ix]['ip'] == self.records[jx]['ip']:
                    if self.records[ix]['is_auto']:
                        self.records[jx]['nftfwaction'] = 'duplicate'
                    else:
                        self.records[ix]['nftfwaction'] = 'duplicate'

    def lookupindb(self):
        """ Lookup ip addresses in the firewall database
        if it exists
        """

        if not self.have_firewall_db:
            return
        # open the database
        fwdb = FwDb(self.cf, createdb=False)
        for rec in self.records:
            if not self.cf.skiprecord(rec) \
               and rec['is_auto']:
                rec['in_nftfwdb'] = fwdb.lookup_by_ip(rec['ip'])
        fwdb.close()

    @staticmethod
    def yesno(istrue):
        """ Visibly print boolean values """

        return 'Yes' if istrue else 'No'

    def print_records(self, title):
        """ Print records """

        print(title)

        pt = PrettyTable()

        if self.is_disabled:
            print('disabled file will be created to inhibit operation.')

        col1 = f'Files to be created'
        if self.is_blacklist:
            pt.field_names = [col1, 'Update database?']
        else:
            pt.field_names = [col1]

        ignore = []
        duplicate = []
        for rec in self.records:
            if rec['nftfwaction'] == 'ignore':
                ignore.append(rec['outname'])
                continue
            if rec['nftfwaction'] == 'duplicate':
                duplicate.append(rec['outname'])
                continue
            out = [rec['outname']]
            if self.is_blacklist:
                out.append(self.yesno(rec['is_auto'] and not rec['in_nftfwdb']))

            pt.add_row(out)

        # set up format
        pt.align = 'l'
        print(pt)

        if ignore:
            print('These files not included, their names are not valid IP addresses:')
            print(", ".join(ignore))
            print()
        if duplicate:
            print('These files not included, their ip address is already defined:')
            print(", ".join(duplicate))
            print()


if __name__ == '__main__':
    # pylint: disable=unused-import,invalid-name
    from pprint import pprint
    from config import Config
    try:
        cf = Config()
    except ConfigError as e:
        print(str(e))
        sys.exit(1)

    ls = ProcessLists(cf, 'blacklist')
    #print('Blacklist')
    #pprint(ls.records)
    ls.print_records('Blacklist')
    ls = ProcessLists(cf, 'whitelist')
    #print('Whitelist')
    #pprint(ls.records)
    ls.print_records('Whitelist')
