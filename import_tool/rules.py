""" Generate the installation instructions for one of
incoming.d and outgoing.d.

Reads the setup from Sympl/Symbiosis and prints actions that will be taken

"""

import sys
import re
import socket

from prettytable import PrettyTable
from configerr import ConfigError

class ProcessRules:
    """Process a single directory to create installation instructions for
    incoming.d or outgoing.d

    The records array contains dictionaries with the following fields:

    sourcepath:   Path of original file
    prefix:       Two character prefix of the rule
    baseaction:   Original action type - remainder of file after '-'
    contents:     File contents
    stat:         Stat of the file
    Added by code
    nftfwaction:   Translated action for nftfw
                   can be set to ignore and unknown
    nftfwlocal:    Set when the rule is in nftfw's local.d
    srclocal:      Was a rule in sympl/symbiosis local.d
    actiontype:    Type of action
                   port - file is a specific port
                   service - file is a service
                   rule - file is a rule
                   local rule - file is a rule in local.d
    expanded:      The baseaction matches an expansion set
                   and baseaction is then set to the new targets
    origaction:    The baseaction before expansion
    outname:       Name of file when creating a new one
    """

    # pylint: disable=redefined-outer-name,invalid-name

    def __init__(self, cf, dirstem):
        """Called with the config class and a directory key to process """

        self.cf = cf
        # setup in config.py
        srcpath = cf.paths['src'][dirstem]

        # enforce strict checking on the name, assisting
        # emacs users that might get ~ appended to the name
        strict = re.compile(r'[0-9][0-9]-[-_a-z0-9]*$', re.I)
        # Generate a list of dictionaries
        self.records = [{'sourcepath':p,
                         'prefix': p.stem[0:2],
                         'baseaction': p.stem[3:],
                         'contents': p.read_text(),
                         'stat': p.stat()}
                        for p in sorted(srcpath.glob('[0-9][0-9]-*'))
                        if strict.match(p.stem) is not None
                        and p.is_file()]
        self.compile()
        self.add_installnames()

    def search_for_action(self, outin, findme):
        """ Look for an action in the local and rule directories

        Returns
        -------
        tuple:   str - translated rulename
                 boolean - True if a local rule

        """

        rules = self.cf.rules[outin]
        if findme in rules['local']:
            return (rules['local'][findme], True)
        if findme in rules['rule']:
            return (rules['rule'][findme], False)
        return (None, None)

    @staticmethod
    def lookup_service(servname):
        """ Use socket to lookup a service

        Returns True if OK
        False otherwise
        """

        try:
            socket.getservbyname(servname)
        except OSError:
            return False
        return True

    def prescan(self):
        """ Scan Sympl/Symbiosis records to check for:
        ports - if so add an nftfw action
        renames - to add in the replacement records
        ignores - records to remove because they are not needed

        Returns: list of records
        """

        newrecords = []
        for rec in self.records:
            if rec['baseaction'].isnumeric():
                rec['nftfwaction'] = rec['baseaction']
                rec['actiontype'] = 'port'
            else:
                # we have some text - look for it in the Sympl/Symbiosis list
                srcname, is_local = self.search_for_action('src', rec['baseaction'])
                if srcname:
                    # record if it's local
                    if is_local:
                        rec['srclocal'] = is_local
                    # it's an action from Sympl/Symbiosis - and it's been translated
                    # into an action with a file
                    if srcname in self.cf.rules_to_ignore:
                        # is this action we ignore
                        rec['nftfwaction'] = 'ignore'
                    elif srcname in self.cf.rules_to_rename:
                        for newaction in self.cf.rules_to_rename[srcname]:
                            newrec = rec.copy()
                            newrec['expanded'] = True
                            newrec['origaction'] = rec['baseaction']
                            newrec['baseaction'] = newaction
                            newrecords.append(newrec)
                        continue
            newrecords.append(rec)
        return newrecords

    def compile(self):
        """Process the records deciding what the new action will be

        Modifies the record
        Adds: nftfwaction - the action name nftfw will use
              warning - a warning message

        """

        prescanned = self.prescan()
        newrecords = []
        for rec in prescanned:
            # Lookup output actions
            # prescan may have set some target actions
            if not 'nftfwaction' in rec:
                # is this a known nftfw action?
                nftfwname, is_local = self.search_for_action('nftfw', rec['baseaction'])
                if nftfwname:
                    # yep
                    rec['nftfwaction'] = nftfwname
                    if is_local:
                        rec['nftfwlocal'] = is_local
                    rec['actiontype'] = 'rule in local.d' if is_local else 'rule'
                else:
                    # see if this is a service that we know about
                    if self.lookup_service(rec['baseaction']):
                        rec['nftfwaction'] = rec['baseaction']
                        rec['actiontype'] = 'service'
                    else:
                        rec['nftfwaction'] = 'unknown'
                        rec['actiontype'] = "Unknown"

            # flag recs that were local rules in Sympl/Symbiosis
            if 'srclocal' in rec and not 'nftfwlocal' in rec:
                srcp = str(self.cf.paths['src']['local']) + '/' + rec['baseaction'] + '*'
                rec['actiontype'] = rec['actiontype'] + f' (recode needed from {str(srcp)})'

            newrecords.append(rec)
        self.records = newrecords

    @staticmethod
    def make_filename(prefix, name):
        """ Make filename from prefix and name """

        return prefix+'-'+name

    def make_filename_from_record(self, record, nameix):
        """Make filename from a record

        nameix is the key for the name to use
        """

        return self.make_filename(record['prefix'], record[nameix])

    def add_installnames(self):
        """ Add the name 'srcname' and 'outname' that will be used for output """

        for rec in self.records:
            ix = 'origaction' if 'origaction' in rec else 'baseaction'
            rec['srcname'] = self.make_filename_from_record(rec, ix)

            outname = ""
            if rec['nftfwaction'] == 'ignore':
                continue
            elif rec['nftfwaction'] == 'unknown':
                outname = '---'
            else:
                outname = self.make_filename_from_record(rec, 'nftfwaction')
            rec['outname'] = outname

    def print_records(self, title):
        """ Print the records  """

        print(title)

        pt = PrettyTable()

        systype = self.cf.system_type
        pt.field_names = [f'{systype} installed cmds',
                          'ntftw cmds',
                          'Installed action type']

        ignore = []
        for rec in self.records:
            if rec['nftfwaction'] == 'ignore':
                ignore.append(rec['srcname'])
                continue
            pt.add_row([rec['srcname'],
                        rec['outname'],
                        rec['actiontype']])
        # set up format
        pt.align = 'l'
        print(pt)

        if ignore:
            print('These files not included, they are handled in nftfw_ini.nft:')
            print(", ".join(ignore))
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

    ruleset = ProcessRules(cf, 'incoming')
    #print('Incoming')
    #pprint(ruleset.records)
    ruleset.print_records('Incoming - incoming.d')

    ruleset = ProcessRules(cf, 'outgoing')
    #print('Outgoing')
    # pprint(ruleset.records)
    ruleset.print_records('Outgoing - outgoing.d')
