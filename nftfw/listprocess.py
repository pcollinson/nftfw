"""nftfw ListProcess class

Generates nft commands for whitelist and blacklist directories
using data structiure created by listreader
"""

import logging
from ruleserr import RulesReaderError
log = logging.getLogger('nftfw')

class ListProcess:
    """Process data from whitelist & blacklist

    Takes data structure from listreader and generates
    1. Sets to specify the ip addresses to be used for the rules
    2. Initialisers to create or flush the sets
    3. nftables code lines to action the rules

    The sets may appear and disappear, so it's not
    easy to make a single re-entrant set of commands.
    When sets are not present an add statement is needed,
    when they are online a flush statement can be used to empty them.

    These are generated separately to allow selective updates.

    Attributes
    ----------
    For the specific listtype - blacklist or whitelist
    this class creates:

    set_init : Dict[key, Dict[proto: contents]
        Contains the commands used to create and reload the sets
        The create rules are used for a complete table reload
        The update rules when just a set needs to be reloaded
        key : {'create', 'update'}
        value is a Dict
            proto : {'ip', 'ip6'}
            contents: str
                ntftables commands to create or update sets

    set_cmds : Dict[key: contents]
        Contain commands used to populate the sets

        key : {'ip', 'ip6'}
        contents : string containing nftables commands

    list_cmds : Dict[key: contents]
        Contain commands used to add rules accessing the sets
        to the appropriate nftables chain

        key : {'ip', 'ip6'}
        contents : string containing nftables commands
    """

    def __init__(self, cf, listtype, records):
        """Initialise

        Parameters
        ----------
        cf : Config
        listtype : {'blacklist', 'whitelist'}
        records: Dict[ports : Dict[content]]
            Records from listreader
            ports : str
                Comma separated list of ports that the
                content applies to.
            content: Dict[
                ip : List[str]
                    List of ip4 addresses - may be empty
                ip6 : List[str]
                    List of ip6 addresses - may be empty
                name : str
                    Name to be used for this nftables set
                ]
        """

        self.cf = cf
        self.listtype = listtype
        self.records = records
        # get config data
        self.nftconfig = cf.get_ini_values_by_section('Nft')

        # Generate data as properties so several files can be written
        # Commands to initialise the sets
        self.set_init = {'create': {"ip": "", "ip6": ""},
                         'update': {"ip": "", "ip6": ""}}
        # Commands to populate the sets
        self.set_cmds = {"ip": "", "ip6": ""}
        # Commands to populate the tables
        self.list_cmds = {"ip": "", "ip6": ""}


    def generate(self):
        """Generate information

        Main entry point from fwmanage
        """

        # add flushes to clear the main chain
        for ip in ('ip', 'ip6'):
            self.list_cmds[ip] += f'flush chain {ip} filter {self.listtype}\n'

        # cycle through the ports we have to make sets for process any
        # 'all' specs first
        if 'all' in self.records.keys():
            self.genone('all')
        # now do the rest
        for key in self.records.keys():
            if key != 'all':
                self.genone(key)

    def genone(self, key):
        """Process one record set

        Parameters
        ----------
        key : str
            Key in records to process
        """

        setinfo = self.records[key]
        # generate headers
        self.genheaders(key)
        # don't generate sets that are not needed
        # for a particular protocol
        for ip in ('ip', 'ip6'):
            if ip in setinfo.keys():
                cmds = self.gensets(key, ip)
                self.set_cmds[ip] += '' if cmds == '' else cmds
                cmds = self.gencmds(key, ip)
                self.list_cmds[ip] += '' if cmds == '' else cmds

    def genheaders(self, key):
        """Load the alternate headers for each types of protocol

        Parameters
        ----------
        key : str
            Key in records to process
        """

        setinfo = self.records[key]
        setname = setinfo['name']

        ixauto = self.listtype + '_set_auto_merge'
        automerge = self.nftconfig[ixauto]

        for ip, adtype in (('ip', 'ipv4_addr'),
                           ('ip6', 'ipv6_addr')):
            if ip in setinfo.keys():
                # create the set
                # NB {{ and }} replaced by single braces
                if automerge:
                    settype = f'{{type {adtype}; flags interval; auto-merge;}}'+"\n"
                else:
                    settype = f'{{type {adtype}; flags interval;}}'+"\n"
                app = f'add set {ip} filter {setname} ' + settype
                self.set_init['create'][ip] += app
                # update the set
                app = f'flush set {ip} filter {setname}\n'
                self.set_init['update'][ip] += app

    def gensets(self, key, proto):
        """Generate set contents

        Parameters
        ----------
        key : str
            Key in records to process
        proto : {'ip', 'ip6'}

        Returns
        -------
        str
           nftables commands or ""
        """

        setinfo = self.records[key]

        if proto in setinfo.keys():
            l = '{' + ",".join(setinfo[proto]) + '}'
            fmt = "# Set for ports {0}\nadd element {1} {2} {3} {4}\n"
            return fmt.format(key, proto,
                              'filter', setinfo['name'], l)
        return ""

    def gencmds(self, key, proto):
        """Generate commands accessing the rules

        Parameters
        ----------
        key : str
            Key in records to process
        proto : {'ip', 'ip6'}

        Returns
        -------
        str
           nftables commands or ""

        """

        setinfo = self.records[key]
        # step 1 make the environment
        env = {'DIRECTION':'incoming',
               'TABLE':'filter',
               'CHAIN': self.listtype,
               'IPS': '@'+setinfo['name'],
               'PROTO': proto}
        if key != 'all':
            if ',' in key:
                env['PORTS'] = '{' + key + '}'
            else:
                env['PORTS'] = key

        #
        # set up COUNTER and LOGGING in the environment
        #
        # to make the shell scripts easier
        # LOGGER is formatted as
        # log prefix "<STRING> "
        # extra space added at the end of the string
        #
        ixc = self.listtype + "_counter"
        if self.nftconfig[ixc] is not None:
            env['COUNTER'] = 'counter'

        ixh = self.listtype + "_logging"
        if self.nftconfig[ixh] is not None:
            pref = self.nftconfig[ixh]
            env['LOGGER'] = f'log prefix "{pref} "'
        # Make rules
        action = self.cf.get_ini_value_from_section('Rules', self.listtype)
        try:
            return self.cf.rulesreader.execute(action, env)
        except RulesReaderError as e:
            log.error(str(e))
            return ''

    @staticmethod
    def collect(adict):
        """ Collect all data from dict indexed by ip or ip6

        Parameters
        ----------
        adict : Dict as described in __init__

        Returns
        ------
        str
            IP addresses separated by new lines
        """

        out = []
        for ip in ['ip', 'ip6']:
            out.append(adict[ip].strip())
        return '' if not any(out) else "\n".join(out) + "\n"

    def get_set_init_create(self):
        """Return create set rules as a string"""

        return self.collect(self.set_init['create'])

    def get_set_init_update(self):
        """Return update set rules as a string"""

        return self.collect(self.set_init['update'])

    def get_set_cmds(self):
        """Return commands to populate sets as a string"""

        return self.collect(self.set_cmds)

    def get_list_cmds(self):
        """Return commands to populate list table as a string"""

        return self.collect(self.list_cmds)
