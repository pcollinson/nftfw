#!/usr/bin/env python3
# pylint: disable=too-many-lines
"""Analyse nft state.

This script reads in the current nftables information
and aggregates the counters in various parts of the
firewall.

First, it shows the overall packet movement through the firewall,
it only deals with packets that are attempting to connect. The nftfw
firewall has a set of chains that are used sequentially to filter incoming
packets. These are calls to whitelist, blacknets, blacklist and incoming.
The latter is the main firewall. Each of these calls have counters, and
by subtraction the number of packets filtered by each chain can be evaluated.
If a packet is not filtered by the firewall it is dropped. So it's possible
to understand what is happening to the inbound traffic.

Second, it examines the counter stored in the firewall and prints a table
displays the connect packets for the different protocols that are open on the
firewall.
"""

from pathlib import Path
import os
import sys
import json
import socket
from subprocess import Popen, PIPE
import argparse
from typing import Any, Optional, Union
from pprint import pp
from prettytable import PrettyTable

USE_ITALIC_IN_TEXT = True

# Data collection
# 'targetvalue' => { 'chain': chainname, 'expr'=>{Lookupdict}}
# Lookupdict contains
# dict elements that must be found in the expr value, which are
# a key that must be found plus partially matching values:
#    a constant dict, where the specified keys must match the given values
#    but other elements can be present in the key:value list
#    PACKETS  used to obtain packet values from the 'packets' key
#
dataparse: dict[str, dict[str, Any]] = {
    # The idea here is to allow changes in the way that
    # the nftfw firewall is set up
    # Pick up basic values from input chain
    # Using these will count main input packet totals
    # These counts are the number of packets passed into
    # the called chain - so
    # Whitelisted packets = blacknets_ct - whitelist_ct
    # Blacknets packets = blacklist_ct - blacknets_ct
    # Blacklist packets = incoming_ct - blacklist_ct
    # Accepted packets = incoming_ct -
    #                            (dropped_ct +
    #                             reject_tcp_ct +
    #                             reject_udp_ct)
    'whitelist_ct': { 'chain': 'input',
                  'expr':  {'counter': {'packets': 'PACKETS'},
                            'jump': {'target': 'whitelist'}}},
    'blacknets_ct': { 'chain': 'input',
                      'expr':  {'counter': {'packets': 'PACKETS'},
                                'jump': {'target': 'blacknets'}}},
    'blacklist_ct': { 'chain': 'input',
                      'expr':  {'counter': {'packets': 'PACKETS'},
                                'jump': {'target': 'blacklist'}}},
    'incoming_ct':  { 'chain': 'input',
                      'expr':  {'counter': {'packets': 'PACKETS'},
                                 'jump': {'target': 'incoming'}}},
    'incoming_drop': {'chain': 'incoming',
                      'expr':  {'counter': {'packets': 'PACKETS'},
                                'jump': {'target': 'dropcounter'}}},
}
# strings used in display columns
coltext: dict[str, str] = {
    'ip_connects':      'IP connects',
    'whitelist_packets': 'Whitelist',
    'blacknets_packets': 'Blacknets',
    'blacklist_packets': 'Blacklist',
    'incoming_packets':  'To firewall',
    'actioned':          'Accepted packets',
    'tcp_dropped':       'Dropped packets',
}

class ReadRules:
    """Read and parse JSON rules from nftables or a file.

    This class reads nftables configuration data, either from the kernel
    or from a file, and parses the JSON to create indexed rule structures.
    Supports both IPv4 and IPv6 rule processing.

    Attributes:
        rules: List of all rules extracted from nftables JSON.
        ixrules: Dictionary of rules indexed by chain name.
        datacounts: Dictionary of packet counts extracted from rules.
        usagecounts: Dictionary of computed usage statistics.
        portsused: Dictionary of port usage statistics by service name.
    """

    def __init__(self, optargs: argparse.Namespace) -> None:
        """Initialise ReadRules with nftables data.

        Loads nftables data either from a file or by querying the kernel,
        parses the JSON structure, and indexes rules by chain.

        Args:
            optargs: Namespace containing program arguments with attributes:
                - file: Optional path to JSON file to read
                - ip6: Boolean indicating whether to read IPv6 data

        Raises:
            SystemExit: If nft command fails to execute.
        """

        output_str: str
        if optargs.file is not None:
            pa = Path(optargs.file)
            output_str = pa.read_text(encoding='UTF8')
        else:
            src = "ip"
            if optargs.ip6:
                src = "ip6"
            with Popen(("nft", "--json", "list", "ruleset", src), stdout=PIPE) as proc:
                (output_bytes, _) = proc.communicate()
                exit_code = proc.wait()
                if exit_code:
                    sys.exit(1)
                output_str = output_bytes.decode('utf-8')

        nfdata = json.loads(output_str)
        nf = nfdata['nftables']
        rulesrc = [r for r in nf if 'rule' in r]
        self.rules: list[dict[str, Any]] = [r['rule'] for r in rulesrc]
        flatrules = self.justexpr(self.rules)
        self.ixrules: dict[str, list[dict[str, Any]]] = self.index_by_chain(flatrules)

        # values created by analyse and friends
        self.datacounts: dict[str, int] = {}
        self.usagecounts: dict[str, int] = {}
        self.portsused: dict[str, int] = {}

    def justexpr(self, rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Filter rules to only those with expr and flatten the expr structure.

        Processes a list of rule dictionaries, keeping only those that contain
        an 'expr' key, and flattens the expr value from a list to a dict.

        Args:
            rules: List of rule dictionaries from nftables JSON.

        Returns:
            List of rules containing only those with flattened expr values.
        """

        flatexpr: list[dict[str, Any]] = []
        for elem in rules:
            if 'expr' in elem:
                elem['expr'] = self.flatten(elem['expr'])
                flatexpr.append(elem)
        return flatexpr

    def index_by_chain(self, frules: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
        """Index rules by their chain name.

        Converts a flat list of rules into a dictionary where keys are chain
        names and values are lists of rules belonging to that chain.

        Args:
            frules: List of rule dictionaries to index.

        Returns:
            Dictionary mapping chain names to lists of rules.
        """

        addix: dict[str, list[dict[str, Any]]] = {}
        for elem in frules:
            ix = elem['chain']
            if ix not in addix:
                addix[ix] = []
            addix[ix].append(elem)
        return addix

    def flatten(self, expr: list[dict[str, Any]]) -> dict[str, Any]:
        """Convert expr from a list of dicts to a single dict.

        Flattens the expr structure by merging all dictionaries in the list.
        Handles duplicate keys by converting them to lists.

        Note:
            If multiple 'match' statements exist in a rule, only the last
            one will be visible in the flattened structure, unless they
            are converted to a list.

        Args:
            expr: List of expression dictionaries to flatten.

        Returns:
            Single dictionary with merged expression data.
        """

        out: dict[str, Any] = {}
        for item_dict in expr:
            for key, value in item_dict.items():
                # cope with duplicate keys that are rare
                if key in out:
                    if isinstance(out[key], dict):
                        newd: list[Any] = [out[key], value]
                        out[key] = newd
                    elif isinstance(out[key], list):
                        out[key].append(value)
                else:
                    out[key] = value
        return out

    # Processing code starts here

    def analyse(self, pparse: dict[str, dict[str, Any]]) -> None:
        """Analyse nftables data to extract packet counts and usage statistics.

        Extracts basic packet counts from the rules, computes usage statistics
        through arithmetic operations, and inspects port usage if packets were
        actioned.

        Args:
            pparse: Dictionary containing parse configuration for extracting
                   packet counts from different chains.
        """

        self.datacounts = self.getcounts(pparse)
        # datacounts is a dict, indexed by the names in dataparse
        # the counts from dataparse are entry counts into
        # firewall sections. The difference between one line
        # and the next show the packets consumed by the
        # firewall rule.
        self.usagecounts = self.makeusage()
        # Now let's find out how the actioned packets were used
        if self.usagecounts['actioned'] != 0:
            self.ports_inspect()

    def getcounts(self, pparse: dict[str, dict[str, Any]]) -> dict[str, int]:
        """Extract packet counts from rules based on parse configuration.

        Scans through indexed rules and matches them against the parse
        configuration to extract packet counter values.

        Args:
            pparse: Dictionary mapping counter names to chain and expression
                   match patterns.

        Returns:
            Dictionary mapping counter names to packet count values.
        """

        # initialise results
        out: dict[str, int] = {key: 0 for key in pparse}
        # chains we need to look at
        chains: set[str] = set()
        for key in pparse:
            chains.add(pparse[key]['chain'])
        # now scan data from rules
        for chain, rlist in self.ixrules.items():
            if chain not in chains:
                continue
            # rlist contains the data to parse for this chain
            for possible in rlist:
                for valuekey, matchdata in pparse.items():
                    if matchdata['chain'] != chain:
                        continue
                    # so the chains match
                    # matchdata['expr'] needs to match possible['expr]
                    (matched, value) = self.datamatch(matchdata['expr'], possible['expr'])
                    if matched:
                        out[valuekey] += value
        return out

    def datamatch(self, refexpr: dict[str, Any],
                  pexpr: dict[str, Any]) -> tuple[bool, int]:
        """Recursively match reference expression against parsed expression.

        Compares two dictionaries to determine if the parsed expression (pexpr)
        matches the reference pattern (refexpr). Extracts packet count values
        when the special 'PACKETS' marker is found.

        Args:
            refexpr: Reference expression pattern to match against.
            pexpr: Parsed expression from nftables data.

        Returns:
            Tuple of (matched, value) where matched is True if expressions
            match and value is the extracted packet count.
        """
        # pylint: disable=too-many-branches
        value = 0

        # first check that all the keys we have in refexpr also exist in pexpr
        allkeys = [k for k in refexpr if k in pexpr]
        if len(allkeys) != len(refexpr.keys()):
            return (False, 0)
        # keys are there look at values
        matchedkeys: dict[str, bool] = {k: False for k in refexpr}
        for key in refexpr:
            # do we have ints as values and those ints are equal
            if isinstance(refexpr[key], int) and isinstance(pexpr[key], int):
                if refexpr[key] == pexpr[key]:
                    matchedkeys[key] = True
                    continue
                return (False, 0)
            # do we have str as the source value and the str is 'PACKETS'
            # and the pexpr value is numeric or both are str and are equal
            if isinstance(refexpr[key], str):
                if refexpr[key] == 'PACKETS' and isinstance(pexpr[key], int):
                    value = pexpr[key]
                    matchedkeys[key] = True
                    continue
                if isinstance(pexpr[key], str) and refexpr[key] == pexpr[key]:
                    matchedkeys[key] = True
                    continue
                return (False, 0)
            # do we have a dict as a source value
            if isinstance(refexpr[key], dict) and isinstance(pexpr[key], dict):
                matchedkeys[key], val = self.datamatch(refexpr[key], pexpr[key])
                if matchedkeys[key]:
                    value += val
            # rarely we may have a list of dicts as the value
            # so any matching needs to mirror that
            if isinstance(refexpr[key], list) and isinstance(pexpr[key], list):
                for lvd in refexpr[key]:
                    if lvd in pexpr[key]:
                        matchedkeys[key] = True

        if False in matchedkeys.values():
            return (False, 0)
        return (True, value)

    def makeusage(self) -> dict[str, int]:
        """Compute usage statistics from raw packet counts.

        Uses arithmetic on datacounts to determine how many packets were
        processed by each firewall section (whitelist, blacknets, blacklist,
        etc.).

        Returns:
            Dictionary mapping statistic names to computed packet counts.
        """

        out: dict[str, int] = {}
        # This matches the order of these statements in the incoming chain
        datac = self.datacounts
        out['ip_connects'] = datac['whitelist_ct']
        out['whitelist_packets'] = \
            datac['whitelist_ct'] - datac['blacknets_ct']
        out['blacknets_packets'] = \
            datac['blacknets_ct'] - datac['blacklist_ct']
        out['blacklist_packets'] = \
            datac['blacklist_ct'] - datac['incoming_ct']
        out['incoming_packets'] = datac['incoming_ct']
        out['actioned'] = \
            out['incoming_packets'] - datac['incoming_drop']
        out['tcp_dropped'] = datac['incoming_drop']
        return out

    def ports_inspect(self) -> None:
        """Inspect incoming chain to determine port usage by service.

        Examines the 'incoming' chain rules to extract packet counts
        for different ports and protocols, mapping them to service names.
        Results are stored in self.portsused.
        """

        inspect = self.ixrules['incoming']
        for elem in inspect:
            if 'expr' not in elem:
                continue
            expr = elem['expr']
            if 'counter' not in expr or \
               'packets' not in expr['counter'] or \
               expr['counter']['packets'] == 0:
                continue
            # test for accepts
            if 'accept' not in expr or \
               expr['accept'] is not None:
                continue
            packets = expr['counter']['packets']
            protocol: Optional[str] = None
            port: Optional[int] = None
            if 'match' in expr:
                match = expr['match']
                if 'left' in match:
                    if 'payload' in match['left']:
                        if 'protocol' in match['left']['payload']:
                            protocol = match['left']['payload']['protocol']
                        if 'right' in match:
                            port = match['right']
            if protocol is not None and port is not None and isinstance(port, int):
                pname = self.getservice(protocol, port)
                self.portsused[pname] = packets

    @staticmethod
    def getservice(proto: str, port: int) -> str:
        """Get service name for a given protocol and port.

        Attempts to resolve the port number to a service name using the
        system service database. Falls back to numeric port if not found.

        Args:
            proto: Protocol name (e.g., 'tcp', 'udp').
            port: Port number.

        Returns:
            String in format 'protocol: servicename' or 'protocol: port'.
        """

        try:
            name = socket.getservbyport(port, proto)
            return f'{proto}: {name}'
        except OSError:
            return f'{proto}: {port}'



class Showtable:
    """Display formatted table of firewall usage statistics.

    This class creates and displays a table showing packet statistics
    for IPv4 and/or IPv6, including counts and percentages.

    Attributes:
        optargs: Program arguments namespace.
        colnames: Dictionary mapping statistic keys to display names.
        rrip: ReadRules instance for IPv4 data (can be None).
        rrip6: ReadRules instance for IPv6 data (can be None).
        colmap: List of booleans indicating which column sets to display.
        pertotal: List of total packet counts for percentage calculations.
        percols: List of column names that should use percentage formatting.
    """

    # pylint: disable=too-many-instance-attributes

    def __init__(self, optargs: argparse.Namespace, colnames: dict[str, str],
                 rrip: Optional[ReadRules], rrip6: Optional[ReadRules]) -> None:
        """Initialise Showtable with data from ReadRules instances.

        Creates data structure for PrettyTable display with flexible column
        layout based on which data sources are available.

        Args:
            optargs: Program arguments namespace.
            colnames: Dictionary mapping statistic keys to display names.
            rrip: ReadRules instance for IPv4 data (None to suppress).
            rrip6: ReadRules instance for IPv6 data (None to suppress).

        Raises:
            SystemExit: If neither IPv4 nor IPv6 data is available.

        Note:
            Column layout varies based on available data:
            - Both IP/IP6: Shows IP counts/%, IP6 counts/%, Total counts/%
            - IP only: Shows IP counts/%
            - IP6 only: Shows IP6 counts/%
        """

        self.optargs = optargs
        self.colnames = colnames
        self.rrip = rrip
        self.rrip6 = rrip6

        # how many columns are we making
        self.colmap: list[bool] = [True, True, True]
        if rrip is None:
            self.colmap[0] = False
            self.colmap[2] = False
        if rrip6 is None:
            self.colmap[1] = False
            self.colmap[2] = False
        if True not in self.colmap:
            print("Not enough data")
            sys.exit(1)

        # Ability to change percentage total values
        # for different columns
        self.percentbase: Optional[str] = None

        # The idea is that just before we add the
        # row for the data, the values in pertotal
        # are updated from the right data source
        # for that part of the table. This will
        # generate a more relevant percentage
        # value.
        self.percentmatch: dict[str, str] = {
            'ip_connects': 'ip_connects',
            'actioned': 'incoming_packets'
            }

        # for working out percentages for each row
        self.pertotal: list[int] = [0, 0, 0]

        # we need to start here because it needs to make
        # the header row
        self.set_percent_totals('ip_connects')

        # custom format for percentages
        self.percols: list[str] = []

    def set_percent_totals(self, key: str) -> bool:
        """ Set the values on self.pertotal based on
        usage data from a known key. This gets called
        every time from the table generation code before
        the row is added.

        Returns True if the values have changed, False
        otherwise
        """

        # We need this to be set to make the header line
        if self.percentbase == key or key not in self.percentmatch:
            return False

        sourcetotal = self.percentmatch[key]
        # remember the name we used last
        # so we can call this sparsely
        self.percentbase = sourcetotal
        if self.colmap[0]:
            assert self.rrip is not None
            self.pertotal[0] = \
                self.rrip.usagecounts[sourcetotal]
        if self.colmap[1]:
            assert self.rrip6 is not None
            self.pertotal[1] = \
                self.rrip6.usagecounts[sourcetotal]
        if self.colmap[2]:
            self.pertotal[2] = \
                self.pertotal[0] + self.pertotal[1]
        return True

    def display(self, optargs: argparse.Namespace) -> None:
        """Generate and display the formatted statistics table.

        Creates a PrettyTable with appropriate column titles, content rows,
        and custom formatting for percentage columns, then prints it.
        """
        titles = self.makecoltitles()
        contents = self.maketable()
        table = PrettyTable()
        if optargs.noborders:
            table.border = False
            table.header = False
        table.field_names = titles
        table.align = "r"
        table.align[titles[0]] = 'l'  # type: ignore[index]
        for pname in self.percols:
            table.custom_format[pname] = self.perfmt  # type: ignore[assignment]
        table.add_rows(contents)
        print(table)

    @staticmethod
    def perfmt(_field: str, val: Union[float, str, int]) -> Union[str, int, float]:
        """Format percentage values for PrettyTable display.

        Args:
            _field: Field name (unused but required by PrettyTable).
            val: Value to format (expected to be float for percentages).

        Returns:
            Formatted percentage string or empty string for non-float values
            or 100.0 values.
        """

        if isinstance(val, float):
            if val == 100.0:
                return ""
            return f'{val:.2f}%'
        return val

    def makecoltitles(self) -> list[Union[str, int, float]]:
        """Generate column titles based on available data sources.

        Creates column headers that vary based on whether IPv4, IPv6,
        or both data sources are available.

        Returns:
            List of column title strings (and values) for the table header.
        """

        title = f'Type ({self.optargs.file})' \
            if self.optargs.file else 'Type'

        return self._setcols(title,
                             ['IP', self.titleper(0)],
                             ['IP6', self.titleper(1)],
                             ['Total', self.titleper(2)],
                             True
                             )

    def makepercentrow(self) -> list[Union[str, int, float]]:
        """Generate extra row when a percentage is changing
        All columns apart from percentages are empty

        Returns:
            List of column title strings (and values) for the
            additional line
        """

        return self._setcols(self.italic('Firewall processing'),
                             ['', self.titleper(0)],
                             ['', self.titleper(1)],
                             ['', self.titleper(2)],
                             False
                             )

    def makeblankrow(self) -> list[Union[str, int, float]]:
        """ Make a blank row """

        return self._setcols("",
                             ['', ''],
                             ['', ''],
                             ['', ''],
                             False
                             )


    def titleper(self, ix: int) -> str:
        """ Format of percent values """

        return f"%/{self.pertotal[ix]}"


    def _setcols(self,
                 title: str,
                 col0: list[str],
                 col1: list[str],
                 col2: list[str],
                 setpercols: bool) -> list[Union[str, int, float]]:
        """Generate row formats for fixed data

        Returns:
            List of column title strings (and values) for the table header.
        """
        # pylint: disable=too-many-positional-arguments,too-many-arguments

        col_titles: list[list[Union[str, int, float]]] = []

        # readable indexes for the col? lists
        txt = 0
        per = 1

        if self.colmap[0]:
            col_titles.append(self.make3col(title, col0[txt], col0[per]))
            if setpercols:
                self.percols.append(col0[per])
        else:
            col_titles.append([title])

        if self.colmap[1]:
            col_titles.append(self.make2col(col1[txt], col1[per]))
            if setpercols:
                self.percols.append(col1[per])

        if self.colmap[2]:
            col_titles.append(self.make2col(col2[txt], col2[per]))
            if setpercols:
                self.percols.append(col2[per])

        titles: list[Union[str, int, float]] = []
        for title_group in col_titles:
            titles = titles + title_group
        return titles


    def italic(self, txt: str) -> str:
        """ Add magic italic markup for text """

        if USE_ITALIC_IN_TEXT:
            return f"\x1B[3m{txt}\x1B[0m"
        return txt

    def maketable(self) -> list[list[Union[str, int, float]]]:
        """Generate all data rows for the table.

        Iterates through usage count keys and creates a row for each
        statistic.

        Returns:
            List of rows, where each row is a list of cell values.
        """

        if self.colmap[0]:
            refip = self.rrip
        else:
            refip = self.rrip6

        assert refip is not None
        table: list[list[Union[str, int, float]]] = []
        for key in refip.usagecounts:
            # check on percentage evaluation
            if self.set_percent_totals(key):
                table.append(self.makeblankrow())
                table.append(self.makepercentrow())
            table.append(self.makerow(key))
        return table

    def makerow(self, key: str) -> list[Union[str, int, float]]:
        """Generate a single data row for a given statistic key.

        Creates row cells with counts and percentages for available
        data sources (IPv4, IPv6, and/or totals).

        Args:
            key: Statistic key from usagecounts dictionary.

        Returns:
            List of cell values for this row.
        """

        row: list[list[Union[str, int, float]]] = []
        c0 = self.colnames[key]
        if self.colmap[0]:
            assert self.rrip is not None
            c1 = self.rrip.usagecounts[key]
            c2 = self.pertotal[0]
            row.append(self.make3col(c0, c1, c2))
        else:
            row.append([c0])

        if self.colmap[1]:
            assert self.rrip6 is not None
            c1 = self.rrip6.usagecounts[key]
            c2 = self.pertotal[1]
            row.append(self.make2col(c1, c2))

        if self.colmap[2]:
            assert self.rrip is not None
            assert self.rrip6 is not None
            c1 = self.rrip.usagecounts[key] + \
                self.rrip6.usagecounts[key]
            c2 = self.pertotal[2]
            row.append(self.make2col(c1, c2))

        out: list[Union[str, int, float]] = []
        for row_section in row:
            out = out + row_section
        return out

    @staticmethod
    def percent(num: int, total: int) -> float:
        """Calculate percentage of num relative to total.

        Args:
            num: Numerator value.
            total: Denominator value.

        Returns:
            Percentage rounded to 2 decimal places, or 0.0 if either
            value is 0.
        """

        if num == 0 or total == 0:
            return 0.0
        numf = float(num)
        totalf = float(total)
        per = numf * 100 / totalf
        return round(per, 2)

    def make3col(self, col_a: str, col_b: Union[str, int],
                 total: Union[str, int]) -> list[Union[str, int, float]]:
        """Create a three-column list with label, count, and percentage.

        Args:
            col_a: Label string for first column.
            col_b: Count value (int) or string label for second column.
            total: Total for percentage calculation (int) or string label.

        Returns:
            List of three values: [label, count/label, percentage/label].
        """

        result_a: str = col_a
        result_b: Union[str, int] = col_b
        result_c: Union[str, float, int]

        if isinstance(col_b, int) and isinstance(total, int):
            if total == 0 or col_b == 0:
                result_b = ""
                result_c = ""
            else:
                result_c = self.percent(col_b, total)
        else:
            result_c = total
        return [result_a, result_b, result_c]

    def make2col(self, col_b: Union[str, int],
                 total: Union[str, int]) -> list[Union[str, int, float]]:
        """Create a two-column list with count and percentage.

        Args:
            col_b: Count value (int) or string label.
            total: Total for percentage calculation (int) or string label.

        Returns:
            List of two values: [count/label, percentage/label].
        """

        result_b: Union[str, int] = col_b
        result_c: Union[str, float, int]

        if isinstance(col_b, int) and isinstance(total, int):
            if total == 0 or col_b == 0:
                result_b = ""
                result_c = ""
            else:
                result_c = self.percent(col_b, total)
        else:
            result_c = total
        return [result_b, result_c]

class Showports(Showtable):
    """Display formatted table of port usage statistics.

    Inherits from Showtable to reuse table formatting code. Shows
    packet counts per service/port for IPv4 and/or IPv6.

    Attributes:
        merged: Dictionary mapping service names to port usage counts
               with keys 'ip', 'ip6', and 'total'.
    """

    # pylint: disable=too-many-instance-attributes
    # Ten is reasonable in this case.

    def __init__(self, optargs: argparse.Namespace,
                 rrip: Optional[ReadRules], rrip6: Optional[ReadRules]) -> None:
        """Initialise Showports with port usage data.

        Creates a merged view of port statistics from IPv4 and/or IPv6
        data sources. Suppresses display if no port data is available.

        Args:
            optargs: Program arguments namespace.
            rrip: ReadRules instance for IPv4 data (None to suppress).
            rrip6: ReadRules instance for IPv6 data (None to suppress).

        Note:
            Exits quietly (status 0) if neither data source has port
            information. Column layout varies based on available data
            similar to Showtable parent class.
            Does not call super().__init__() as it needs custom initialisation.
        """
        # pylint: disable=super-init-not-called
        # Not calling super().__init__ is intentional - custom initialisation needed
        self.optargs = optargs
        self.rrip = rrip
        self.rrip6 = rrip6

        self.havedata = True

        # check we have port data in each of the instances
        if self.rrip is not None and len(self.rrip.portsused) == 0:
            self.rrip = None
        if self.rrip6 is not None and len(self.rrip6.portsused) == 0:
            self.rrip6 = None

        # how many columns are we making
        self.colmap: list[bool] = [True, True, True]
        if self.rrip is None:
            self.colmap[0] = False
            self.colmap[2] = False
        if self.rrip6 is None:
            self.colmap[1] = False
            self.colmap[2] = False
        if True not in self.colmap:
            # just leave quietly
            self.havedata = False
            return

        # Ability to change percentage total values
        # for different columns
        self.percentbase: Optional[str] = None

        # This maps the column in the data
        # to a source for a total
        # The first one is called directly
        # we don't antipate changing the percentage base
        # for the ports information, and we don't know the key
        # anyway
        self.percentmatch: dict[str, str] = {'start': 'actioned'}

        # for working out percentages
        self.pertotal: list[int] = [0, 0, 0]

        self.set_percent_totals('start')

        # custom format for percentages
        self.percols: list[str] = []

        # merge the (possibly) two port lists
        self.merged: dict[str, dict[str, int]] = {}
        self.mergeports()

    def mergeports(self) -> None:
        """Merge port usage data from IPv4 and IPv6 sources.

        Creates a unified dictionary where each service/port has counts
        for IPv4, IPv6, and total traffic.

        The merged dictionary structure is:
            service_name: {'ip': count, 'ip6': count, 'total': count}
        """

        if self.colmap[0]:
            assert self.rrip is not None
            ports = self.rrip.portsused
            for service, count in ports.items():
                self.merged[service] = {'ip': count, 'ip6': 0, 'total': 0}

        if self.colmap[1]:
            assert self.rrip6 is not None
            ports = self.rrip6.portsused
            for service, count in ports.items():
                if service in self.merged:
                    self.merged[service]['ip6'] = count
                else:
                    self.merged[service] = {'ip': 0, 'ip6': count, 'total': 0}

        if self.colmap[2]:
            for service, counts in self.merged.items():
                counts['total'] = counts['ip'] + counts['ip6']

    def makecoltitles(self) -> list[Union[str, int, float]]:
        """Generate column titles for port usage table.

        Overrides parent method to use 'Service' as the first column
        header instead of 'Type'.

        Returns:
            List of column title strings (and values) for the table header.
        """

        col_titles: list[list[Union[str, int, float]]] = []
        c0 = 'Service'
        if self.colmap[0]:
            c1 = "IP"
            c2 = f"%/{self.pertotal[0]}"
            col_titles.append(self.make3col(c0, c1, c2))
            self.percols.append(c2)
        else:
            col_titles.append([c0])

        if self.colmap[1]:
            c1 = f"%/{self.pertotal[1]}"
            col_titles.append(self.make2col('IP6', c1))
            self.percols.append(c1)

        if self.colmap[2]:
            c2 = f"%/{self.pertotal[2]}"
            col_titles.append(self.make2col('Total', c2))
            self.percols.append(c2)

        titles: list[Union[str, int, float]] = []
        for title_group in col_titles:
            titles = titles + title_group
        return titles

    def maketable(self) -> list[list[Union[str, int, float]]]:
        """Generate all data rows for the port usage table.

        Iterates through merged service names and creates a row for
        each service.

        Returns:
            List of rows, where each row is a list of cell values.
        """

        table: list[list[Union[str, int, float]]] = []
        for key in self.merged:
            table.append(self.makerow(key))
        return table

    def makerow(self, key: str) -> list[Union[str, int, float]]:
        """Generate a single data row for a given service.

        Creates row cells with port usage counts and percentages for
        available data sources (IPv4, IPv6, and/or totals).

        Args:
            key: Service name (e.g., 'tcp: ssh', 'udp: 53').

        Returns:
            List of cell values for this row.
        """

        row: list[list[Union[str, int, float]]] = []
        c0 = key
        if self.colmap[0]:
            c1 = self.merged[key]['ip']
            c2 = self.pertotal[0]
            row.append(self.make3col(c0, c1, c2))
        else:
            row.append([key])

        if self.colmap[1]:
            c1 = self.merged[key]['ip6']
            c2 = self.pertotal[1]
            row.append(self.make2col(c1, c2))

        if self.colmap[2]:
            c1 = self.merged[key]['total']
            c2 = self.pertotal[2]
            row.append(self.make2col(c1, c2))

        out: list[Union[str, int, float]] = []
        for row_section in row:
            out = out + row_section
        return out

def am_i_root() -> None:
    """Verify the process is running as root (UID 0).

    Checks the effective user ID and exits with an error message if not
    running as root. This is required because reading nftables data
    requires root privileges.

    Raises:
        SystemExit: Exits with code 1 if not running as root.
    """
    if os.geteuid() != 0:
        print("Run the program as root")
        sys.exit(1)


def progargs() -> argparse.Namespace:
    """Parse and process command-line arguments.

    Sets up argument parser with options for IPv4/IPv6 selection,
    file input, display modes, and debugging. Also sets the runloop
    flag to determine if both IPv4 and IPv6 data should be processed.

    Returns:
        Namespace containing parsed arguments with additional runloop attribute.

    Note:
        runloop is set to True when both IPv4 and IPv6 data should be
        processed (default behaviour or when both -4 and -6 are specified).
    """

    parser = argparse.ArgumentParser(
        description='Analyse nftables firewall statistics and display packet flow information.')
    parser.add_argument('-4', "--ip", action="store_true",
                        help="Read and process IPv4 data only")
    parser.add_argument('-6', "--ip6", action="store_true",
                        help="Read and process IPv6 data only")
    parser.add_argument('-u', '--usage', action="store_true",
                        help="Only print usage data")
    parser.add_argument('-p', '--ports', action="store_true",
                        help="Only print port data")
    parser.add_argument('-f', "--file",
                        help="File to process, reads from kernel if not specified")
    parser.add_argument('-r', '--raw', action="store_true",
                        help="Print decoded data from nftables and exit. "
                             "Prints IPv4 and IPv6 unless -4 or -6 is included")
    parser.add_argument('-n', '--noborders', action="store_true",
                        help="Suppress borders and headers on the output tables")

    args = parser.parse_args()

    # runloop set so that code can run two invocations of ReadRules
    args.runloop = False
    if args.file is None:
        if args.ip and args.ip6:
            args.runloop = True
        elif args.ip is False and args.ip6 is False:
            args.runloop = True
    return args


def runone(options: argparse.Namespace) -> ReadRules:
    """Execute one invocation of ReadRules with analysis.

    Creates a ReadRules instance for the specified IP version and
    runs the analysis on the parsed nftables data.

    Args:
        options: Namespace containing program arguments including
                ip/ip6 flags to determine which data to process.

    Returns:
        ReadRules instance with analysed data.
    """

    read_rules = ReadRules(options)
    read_rules.analyse(dataparse)
    return read_rules


def process(options: argparse.Namespace) -> None:
    """Execute main processing logic based on command-line options.

    Orchestrates the reading, analysis, and display of nftables data.
    Handles both IPv4 and IPv6 data processing, raw data output mode,
    and selective display of usage or port statistics.

    Args:
        options: Namespace containing parsed command-line arguments.

    Raises:
        SystemExit: Exits if no data is available or in raw mode after display.
    """

    # pylint: disable=too-many-branches

    if options.runloop:
        options.ip = True
        options.ip6 = False
        rrip = runone(options)
        if options.raw:
            pp(rrip.ixrules)
        options.ip = False
        options.ip6 = True
    rrip6 = runone(options)
    if options.raw:
        pp(rrip6.ixrules)
        sys.exit(0)

    if options.runloop:
        # Bail out if we have no data
        if rrip.usagecounts['ip_connects'] == 0 and \
           rrip6.usagecounts['ip_connects'] == 0:
            print("No data at present")
            sys.exit(0)
        rrip_copy: Optional[ReadRules] = rrip
        if rrip.usagecounts['ip_connects'] == 0:
            rrip_copy = None
        rrip6_copy: Optional[ReadRules] = rrip6
        if rrip6.usagecounts['ip_connects'] == 0:
            rrip6_copy = None

        showtable = Showtable(options, coltext, rrip_copy, rrip6_copy)
        showports = Showports(options, rrip_copy, rrip6_copy)
    else:
        if rrip6.usagecounts['ip_connects'] == 0:
            print("No data at present")
            sys.exit(0)
        showtable = Showtable(options, coltext, rrip6, None)
        showports = Showports(options, rrip6, None)

    # Default is to print both when no option set
    # or obey the -p or -u option when set
    # if both usage and ports are on, turn them off
    if options.usage and options.ports:
        options.usage = options.ports = False

    # if both are off, or usage is on
    if (not options.usage and not options.ports) or options.usage:
        showtable.display(options)

    # if both are off, or ports is on
    if (not options.usage and not options.ports) or options.ports:
        if showports.havedata:
            showports.display(options)

if __name__ == '__main__':
    pargs = progargs()
    # don't need root for looking at files
    if pargs.file is None:
        am_i_root()
    process(pargs)
