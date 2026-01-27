"""List processor for nftables command generation.

This module generates nftables commands for blacklist, whitelist, and network
blacklist (blacknets) data. It processes records from ListReader or NetReader
and produces three categories of commands: set initialisation, set population,
and rule generation.

Key Features
------------
- Processes records from ListReader (blacklist.d/whitelist.d) or NetReader (blacknets.d)
- Generates nftables set definitions and population commands
- Creates firewall rules using RulesReader shell scripts
- Supports both IPv4 and IPv6 protocols
- Handles port-specific and 'all' port rules
- Provides separate create vs update commands for efficient reloads
- Auto-merge flag support for optimised set storage

Command Categories
------------------
**Set Initialization (set_init):**
    - create: Commands to add new sets (full table reload)
    - update: Commands to flush existing sets (set-only reload)

**Set Population (set_cmds):**
    - Commands to add IP addresses/networks to sets

**Rule Generation (list_cmds):**
    - Commands to add firewall rules that reference the sets

Workflow
--------
1. ListProcess instantiated with records from ListReader/NetReader
2. generate() called to process all records
3. For each port group (process 'all' first, then specific ports):
   - Generate set headers (create/update commands)
   - Generate set contents (IP address lists)
   - Execute rule scripts to generate firewall rules
4. Access results via getter methods:
   - get_set_init_create() → create commands
   - get_set_init_update() → update commands
   - get_set_cmds() → set population commands
   - get_list_cmds() → firewall rule commands

Records Structure
-----------------
Input records dict from ListReader or NetReader::

    {
        'all': {              # Special key for all ports
            'name': 'blacklist_all_set',
            'ip': ['192.0.2.1', '192.0.2.0/24', ...],
            'ip6': ['2001:db8::1', ...]
        },
        '22': {               # SSH port
            'name': 'b_22',
            'ip': ['198.51.100.1', ...],
            'ip6': [...]
        },
        '80,443': {           # HTTP/HTTPS ports
            'name': 'b_80_443',
            'ip': [...],
            'ip6': [...]
        }
    }

Generated Commands Example
---------------------------
For a blacklist with one IP on port 22::

    # Set initialisation (create)
    add set ip filter b_22 {type ipv4_addr; flags interval;}

    # Set population
    add element ip filter b_22 {198.51.100.1}

    # Firewall rule (from blacklist rule script)
    add rule ip filter blacklist tcp dport 22 ip saddr @b_22 counter drop

Usage Example
-------------
From fwmanage.py::

    from .config import Config
    from .listreader import ListReader
    from .listprocess import ListProcess

    cf = Config()
    lr = ListReader(cf, 'blacklist', need_compiled_ix=True)
    lp = ListProcess(cf, 'blacklist', lr.records)
    lp.generate()

    # Get commands for different file variants
    create_cmds = lp.get_set_init_create()  # For *_init.nft
    update_cmds = lp.get_set_init_update()  # For *_update.nft
    set_cmds = lp.get_set_cmds()            # For *_sets_init.nft
    rule_cmds = lp.get_list_cmds()          # For *.nft

See Also
--------
listreader.py : Reads blacklist.d and whitelist.d files
netreader.py : Reads blacknets.d files
firewallprocess.py : Processes firewall rules (incoming.d/outgoing.d)
rulesreader.py : Executes shell scripts to generate rules
fwmanage.py : Main firewall manager that uses ListProcess

"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast
import logging
from .ruleserr import RulesReaderError

if TYPE_CHECKING:
    from .config import Config

log = logging.getLogger('nftfw')


class ListProcess:
    """Process blacklist, whitelist, and network blacklist data into nftables commands.

    Takes records from ListReader or NetReader and generates three categories
    of nftables commands: set initialisation, set population, and firewall rules.
    Handles both IPv4 and IPv6 protocols with port-specific and all-ports rules.

    The class generates commands separately to support different firewall reload
    strategies:
    - Full reload: Use create commands to add new sets
    - Set-only update: Use update commands to flush and refill existing sets

    Attributes
    ----------
    cf : Config
        Configuration instance
    listtype : str
        Type of list being processed: 'blacklist', 'whitelist', or 'blacknets'
    records : dict[str, dict[str, Any]]
        Records from ListReader or NetReader mapping ports to IP data
    nftconfig : dict[str, str]
        Configuration from [Nft] section (counter, logging, auto-merge flags)
    set_init : dict[str, dict[str, str]]
        Set initialisation commands:
        - 'create': {'ip': '...', 'ip6': '...'} - Add new sets
        - 'update': {'ip': '...', 'ip6': '...'} - Flush existing sets
    set_cmds : dict[str, str]
        Set population commands:
        - 'ip': nftables commands to add IPv4 addresses
        - 'ip6': nftables commands to add IPv6 addresses
    list_cmds : dict[str, str]
        Firewall rule commands:
        - 'ip': nftables rules for IPv4
        - 'ip6': nftables rules for IPv6

    Example
    -------
    Processing blacklist data::

        from .config import Config
        from .listreader import ListReader
        from .listprocess import ListProcess

        cf = Config()
        lr = ListReader(cf, 'blacklist', need_compiled_ix=True)
        lp = ListProcess(cf, 'blacklist', lr.records)
        lp.generate()

        # Write commands to separate files
        with open('blacklist_init.nft', 'w') as f:
            f.write(lp.get_set_init_create())
            f.write(lp.get_set_cmds())
            f.write(lp.get_list_cmds())

    Processing network blacklist::

        from .netreader import NetReader
        nr = NetReader(cf, 'blacknets')
        if nr.records:
            lp = ListProcess(cf, 'blacknets', nr.records)
            lp.generate()
            # Access commands via getter methods

    Note
    ----
    The generate() method must be called before accessing any getter methods.
    The class processes 'all' port rules first, then port-specific rules,
    to ensure proper ordering in the generated commands.

    See Also
    --------
    ListReader : Provides records for blacklist/whitelist
    NetReader : Provides records for network blacklists
    RulesReader : Executes shell scripts for rule generation

    """

    def __init__(self,
                 cf: Config,
                 listtype: str,
                 records: dict[str, dict[str, Any]]) -> None:
        """Initialize ListProcess with configuration and records.

        Args:
            cf: Configuration instance
            listtype: Type of list - 'blacklist', 'whitelist', or 'blacknets'
            records: Records from ListReader or NetReader.
                    Structure: {ports: {content}}
                    - ports: str - Comma-separated port list or 'all'
                    - content: dict with keys:
                        - 'ip': list[str] - IPv4 addresses/networks (optional)
                        - 'ip6': list[str] - IPv6 addresses/networks (optional)
                        - 'name': str - nftables set name

        Returns:
            None. Initializes instance attributes for later command generation.

        Note:
            The records parameter structure matches the output from
            ListReader.records or NetReader.records. The generate()
            method must be called after initialisation to populate
            the command attributes.

        Example:
            Standard usage::

                lp = ListProcess(cf, 'blacklist', listreader.records)
                lp.generate()
                cmds = lp.get_list_cmds()

        """
        self.cf: Config = cf
        self.listtype: str = listtype
        self.records: dict[str, dict[str, Any]] = records

        # Get nftables configuration settings
        self.nftconfig: dict[str, str | bool] = cf.get_ini_values_by_section('Nft')

        # Initialize command storage
        # Commands to initialise the sets (create new or flush existing)
        self.set_init: dict[str, dict[str, str]] = {
            'create': {"ip": "", "ip6": ""},
            'update': {"ip": "", "ip6": ""}}

        # Commands to populate the sets with IP addresses
        self.set_cmds: dict[str, str] = {"ip": "", "ip6": ""}

        # Commands to populate the firewall rules
        self.list_cmds: dict[str, str] = {"ip": "", "ip6": ""}

    def generate(self) -> None:
        """Generate all nftables commands from records.

        Main entry point called from fwmanage.py. Processes all records
        and populates set_init, set_cmds, and list_cmds attributes.

        Processing order:
        1. Add chain flush commands
        2. Process 'all' port rules first (if present)
        3. Process specific port rules in arbitrary order

        Returns:
            None. Updates instance attributes as side effect.

        Note:
            Must be called before using any getter methods. The 'all'
            port rules are processed first to ensure they appear at
            the beginning of the generated commands, which can be
            important for rule priority.

        Example:
            Generate and retrieve commands::

                lp = ListProcess(cf, 'blacklist', records)
                lp.generate()  # Must call this first

                # Now safe to access commands
                init_cmds = lp.get_set_init_create()
                set_cmds = lp.get_set_cmds()
                rule_cmds = lp.get_list_cmds()

        """
        # Add flush commands to clear the main chain
        for ip in ('ip', 'ip6'):
            self.list_cmds[ip] += f'flush chain {ip} filter {self.listtype}\n'

        # Process 'all' port specifications first
        if 'all' in self.records.keys():
            self.genone('all')

        # Process remaining port-specific rules
        for key in self.records.keys():
            if key != 'all':
                self.genone(key)

    def genone(self, key: str) -> None:
        """Process one record set (one port group).

        Generates set headers, set contents, and firewall rules for
        a single port group (either 'all' or specific ports like '22' or '80,443').

        Args:
            key: Port specification from records dict.
                 Either 'all' or comma-separated port numbers (e.g., '22', '80,443')

        Returns:
            None. Updates instance attributes (set_init, set_cmds, list_cmds).

        Note:
            This method is called by generate() for each key in records.
            It processes both IPv4 and IPv6 data if present, skipping
            protocols that have no data.

        Example:
            Internal use only (called from generate())::

                # Process all ports
                self.genone('all')

                # Process SSH port
                self.genone('22')

                # Process HTTP/HTTPS ports
                self.genone('80,443')

        """
        setinfo: dict[str, Any] = self.records[key]

        # Generate set headers (create and update commands)
        self.genheaders(key)

        # Process each protocol (only if data exists)
        for ip in ('ip', 'ip6'):
            if ip in setinfo.keys():
                # Generate set contents (IP address lists)
                cmds: str = self.gensets(key, ip)
                self.set_cmds[ip] += '' if cmds == '' else cmds

                # Generate firewall rules
                cmds = self.gencmds(key, ip)
                self.list_cmds[ip] += '' if cmds == '' else cmds

    def genheaders(self, key: str) -> None:
        """Generate set initialisation headers for both create and update.

        Creates the nftables set definition commands for both protocols
        (IPv4 and IPv6) if data exists for that protocol. Generates two
        variants: create (add new set) and update (flush existing set).

        Args:
            key: Port specification from records dict

        Returns:
            None. Updates self.set_init['create'] and self.set_init['update'].

        Note:
            The auto-merge flag is controlled by config settings:
            - blacklist_set_auto_merge
            - whitelist_set_auto_merge
            - blacknets_set_auto_merge (if applicable)

            Auto-merge optimises nftables set storage by automatically
            merging adjacent IP ranges.

        Example:
            Internal use only. Generates commands like::

                # Create variant
                add set ip filter b_22 {type ipv4_addr; flags interval;}

                # Update variant
                flush set ip filter b_22

        """
        setinfo: dict[str, Any] = self.records[key]
        setname: str = setinfo['name']

        # Get auto-merge configuration setting
        ixauto: str = self.listtype + '_set_auto_merge'
        automerge: str | bool = self.nftconfig[ixauto]

        # Generate headers for each protocol
        for ip, adtype in (('ip', 'ipv4_addr'),
                           ('ip6', 'ipv6_addr')):
            if ip in setinfo.keys():
                # Create the set definition
                # Note: {{ and }} in f-string become single braces in output
                if automerge:
                    settype: str = (f'{{type {adtype}; flags interval; '
                                   f'auto-merge;}}\n')
                else:
                    settype = f'{{type {adtype}; flags interval;}}\n'

                app: str = f'add set {ip} filter {setname} ' + settype
                self.set_init['create'][ip] += app

                # Generate flush command for updates
                app = f'flush set {ip} filter {setname}\n'
                self.set_init['update'][ip] += app

    def gensets(self, key: str, proto: str) -> str:
        """Generate set population commands (IP address lists).

        Creates nftables commands to add IP addresses or networks to a set.
        The addresses are sorted for consistent output.

        Args:
            key: Port specification from records dict
            proto: Protocol family - 'ip' (IPv4) or 'ip6' (IPv6)

        Returns:
            nftables command string to populate the set, or empty string
            if no data exists for this protocol

        Note:
            Generated commands use the format:
            add element <proto> filter <setname> {addr1, addr2, ...}

            Addresses are sorted alphabetically for deterministic output.

        Example:
            Internal use only. Generates commands like::

                # Set for ports 22
                add element ip filter b_22 {198.51.100.1, 198.51.100.0/24}

        """
        setinfo: dict[str, Any] = self.records[key]

        if proto in setinfo.keys():
            # Format IP list as comma-separated, sorted values in braces
            iplist: str = '{' + ",\n".join(sorted(setinfo[proto])) + '}'
            fmt: str = "# Set for ports {0}\nadd element {1} {2} {3} {4}\n"
            return fmt.format(key, proto, 'filter', setinfo['name'], iplist)
        return ""

    def gencmds(self, key: str, proto: str) -> str:
        """Generate firewall rules by executing rule scripts.

        Builds environment dict and executes the appropriate rule script
        via RulesReader to generate nftables firewall rules.

        Args:
            key: Port specification from records dict
            proto: Protocol family - 'ip' (IPv4) or 'ip6' (IPv6)

        Returns:
            nftables rule commands from script execution, or empty string
            on error

        Note:
            Environment variables passed to rule script:
            - DIRECTION: 'incoming'
            - TABLE: 'filter'
            - CHAIN: listtype (blacklist/whitelist/blacknets)
            - IPS: '@setname' (reference to nftables set)
            - PROTO: 'ip' or 'ip6'
            - PORTS: port number or {port1,port2} (optional, not for 'all')
            - COUNTER: 'counter' (optional, if enabled in config)
            - LOGGER: 'log prefix "string "' (optional, if enabled in config)

        Example:
            Internal use only. Executes rule script which might return::

                add rule ip filter blacklist tcp dport 22 \\
                    ip saddr @b_22 counter drop

        """
        setinfo: dict[str, Any] = self.records[key]

        # Build environment dict for rule script
        env: dict[str, str] = {
            'DIRECTION': 'incoming',
            'TABLE': 'filter',
            'CHAIN': self.listtype,
            'IPS': '@' + setinfo['name'],
            'PROTO': proto
        }

        # Add port specification (not for 'all')
        if key != 'all':
            if ',' in key:
                # Multiple ports: format as {port1,port2}
                env['PORTS'] = '{' + key + '}'
            else:
                # Single port: use as-is
                env['PORTS'] = key

        # Set up COUNTER in the environment
        ixc: str = self.listtype + "_counter"
        if self.nftconfig[ixc] is not None:
            env['COUNTER'] = 'counter'

        # Set up LOGGING in the environment
        # LOGGER is formatted as: log prefix "<STRING> "
        # (extra space added at the end of the string)
        ixh: str = self.listtype + "_logging"
        if self.nftconfig[ixh] is not None:
            pref: str | bool = self.nftconfig[ixh]
            env['LOGGER'] = f'log prefix "{cast(str, pref)} "'

        # Execute rule script to generate firewall rules
        action: str | bool = self.cf.get_ini_value_from_section('Rules',
                                                                 self.listtype)
        try:
            return self.cf.rulesreader.execute(cast(str, action), env)
        except RulesReaderError as e:
            log.error(str(e))
            return ''

    @staticmethod
    def collect(adict: dict[str, str]) -> str:
        """Collect and concatenate commands from IPv4 and IPv6 dicts.

        Helper method to combine commands from both protocols into a
        single string. Used by all getter methods.

        Args:
            adict: Dictionary with 'ip' and 'ip6' keys containing command strings

        Returns:
            Combined commands separated by newlines, or empty string if
            no commands exist

        Note:
            Strips whitespace from each protocol's commands before combining.
            Returns empty string if both protocols have no commands.

        Example:
            Internal use only::

                # Combine create commands
                result = self.collect(self.set_init['create'])
                # Returns IPv4 commands + newline + IPv6 commands

        """
        out: list[str] = []
        for ip in ['ip', 'ip6']:
            out.append(adict[ip].strip())
        return '' if not any(out) else "\n".join(out) + "\n"

    def get_set_init_create(self) -> str:
        """Return set creation commands for full table reload.

        Gets nftables commands to create new sets (add set ...).
        Used when doing a complete firewall reload where sets don't
        exist yet.

        Returns:
            String containing set creation commands for both IPv4 and IPv6

        Note:
            Must call generate() before using this method.
            These commands go in *_init.nft files.

        Example:
            Access after generation::

                lp.generate()
                create_cmds = lp.get_set_init_create()
                # Use in firewall_init.nft or blacklist_init.nft

        """
        return self.collect(self.set_init['create'])

    def get_set_init_update(self) -> str:
        """Return set flush commands for set-only reload.

        Gets nftables commands to flush existing sets (flush set ...).
        Used when doing a set-only update where sets already exist
        and just need to be emptied before refilling.

        Returns:
            String containing set flush commands for both IPv4 and IPv6

        Note:
            Must call generate() before using this method.
            These commands go in *_update.nft files.

        Example:
            Access after generation::

                lp.generate()
                update_cmds = lp.get_set_init_update()
                # Use in blacklist_update.nft for set-only reloads

        """
        return self.collect(self.set_init['update'])

    def get_set_cmds(self) -> str:
        """Return set population commands.

        Gets nftables commands to add IP addresses to sets
        (add element ...). Used in both full and set-only reloads.

        Returns:
            String containing commands to populate sets with IP addresses
            for both IPv4 and IPv6

        Note:
            Must call generate() before using this method.
            These commands go in *_sets_init.nft and *_sets_update.nft files.

        Example:
            Access after generation::

                lp.generate()
                set_cmds = lp.get_set_cmds()
                # Use in blacklist_sets_init.nft

        """
        return self.collect(self.set_cmds)

    def get_list_cmds(self) -> str:
        """Return firewall rule commands.

        Gets nftables commands generated by rule scripts that reference
        the sets (add rule ...). These are the actual firewall rules that
        perform blocking or allowing actions.

        Returns:
            String containing firewall rule commands for both IPv4 and IPv6

        Note:
            Must call generate() before using this method.
            These commands go in *.nft files (blacklist.nft, whitelist.nft).

        Example:
            Access after generation::

                lp.generate()
                rule_cmds = lp.get_list_cmds()
                # Use in blacklist.nft

        """
        return self.collect(self.list_cmds)
