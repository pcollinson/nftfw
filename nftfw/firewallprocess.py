#!/usr/bin/env python3
""" nftfw firewallprocess class

Called from fwmanage to make nftables commands for incoming
and outgoing control directories
"""

import logging
from .ruleserr import RulesReaderError
log = logging.getLogger('nftfw')

class FirewallProcess:
    """FirewallProcess class

    Takes data structure from FirewallReader

    Generates nftable commands

    """

    def __init__(self, cf, direction, records):
        """Initialise

        Parameters
        ----------
        cf : Config
        direction : {'incoming', 'outgoing'}
        records : List[Dict[
             action : str
                 Action file needed for rule
             direction : str
                 'incoming' or 'outgoing'
             ports : str  optional
                  comma separated ports list
             ipv4 : list[str] optional
                  list of ipv4 addresses
             ipv6 : list[str] optional
                  list of ipv6 addresses
                  ]]
        """

        self.cf = cf
        self.direction = direction
        self.records = records
        self.nftconfig = cf.get_ini_values_by_section('Nft')

    def generate(self):
        """Entry point: Generate nft commands returning a string

        Uses lists of actions generated to make rules for nftables
        adds comments to identify rules

        Generates ip rules and then ip6 rules

        Returns
        -------
        str
            ip4 and ip6 rules concatenated
        """

        # lines output at the end of play
        iplines = ""
        ip6lines = ""
        # Make the sequence of commands
        # re-entrant
        iplines = "flush chain ip filter "+self.direction+"\n"
        ip6lines = "flush chain ip6 filter "+self.direction+"\n"

        for r in self.records:
            iplines += self.runforprotocol(r, 'ip')
            ip6lines += self.runforprotocol(r, 'ip6')
        return iplines + ip6lines

    def runforprotocol(self, r, proto):
        """Run a set of rules for a protocol

        Uses rulesreader execute the action file returning a string
        of Nft rules

        Parameters
        ----------
        r : Dict[]
            As in __init__ single record to process
        proto : {'ip', 'ip6'}

        Returns
        -------
        str
        """

        # step 1 make the environment
        env = {'DIRECTION':self.direction,
               'TABLE':'filter',
               'CHAIN': self.direction}
        #
        # set up COUNTER and LOGGING in the environment
        #
        # to make the shell scripts easier
        # LOGGER is formatted as
        # log prefix "<STRING> "
        # note extra space added at the end of the string
        #
        ixc = self.direction + "_counter"
        if self.nftconfig[ixc] is not None:
            env['COUNTER'] = 'counter'
        ixh = self.direction + "_logging"
        if self.nftconfig[ixh] is not None:
            pref = self.nftconfig[ixh]
            env['LOGGER'] = f'log prefix "{pref} "'

        if 'ports' in r:
            env['PORTS'] = r['ports']

        # set up protocol
        env['PROTO'] = proto

        # add ips
        if proto in r.keys():
            env['IPS'] = self.formatips(r[proto])

        try:
            l = '# Rule: '+r['action']+".sh\n"
            l += self.cf.rulesreader.execute(r['action'], env)
            return l
        except RulesReaderError as e:
            log.error(str(e))
            return ""

    @staticmethod
    def formatips(ips):
        """ Format a list of IPs into a singleton or a set

        Parameters
        ----------
        ips: List
            List of numeric ips

        Returns
        -------
        str
            Comma separated list
            in { } suitable for inclusion
            in nfttables command
        """

        if len(ips) == 1:
            return ips[0]
        return '{' + ",".join(ips) + '}'
