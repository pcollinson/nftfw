"""Package structure documentation for nftfw.

Note: This file is intentionally excluded from pylint (see Makefile).
It serves purely as documentation and contains no executable code.

This module provides comprehensive documentation of all files in the nftfw
package and their purposes. It serves as a high-level architectural reference
for developers working with the codebase.

Requirements:
    Python 3.9+ required for modern type hints and annotations.

Files in nftfw - and a description of what they do
===================================================

Package Infrastructure
----------------------

PackageIndex.py        This file - comprehensive package documentation
__init__.py            Package initialization and version information

Main nftfw Application
----------------------

__main__.py            Main application entry point, handles argument parsing
                       and dispatches to actions via Scheduler
config.py              Class Config - central configuration management system:
                       - Compiled default settings
                       - Reads config.ini file overrides
                       - Command-line argument overrides
                       - Logging configuration via LoggerManager
loggermanager.py       Manages Python logging system for controlled output
                       to terminal and log files
stdargs.py             Decodes standard arguments (-q, -v, -o) for nftfw
                       and nftfwadm utilities

Core Utilities
--------------

locker.py              Filesystem-based locking mechanism to prevent
                       concurrent execution
sqdb.py                Class SqDb - base class providing simple SQLite3
                       database interface
fileposdb.py           Class FileposDB - tracks log file read positions
                       for incremental scanning (inherits from SqDb)
fwdb.py                Class FwDb - blacklist database interface with
                       IP tracking and statistics (inherits from SqDb)
scheduler.py           Command orchestration and queuing system:
                       - Provides locking for commands
                       - Queues system commands when lock is held
                       - Distinguishes system vs user commands
stats.py               Time formatting utilities for durations and frequencies

Nftfw Firewall Management ('load' action)
------------------------------------------

fwmanage.py            Main firewall management orchestration:
                       - 8-step workflow from load to install
                       - Handles full installs and set-only updates
                       - Backup and rollback mechanism
 rulesreader.py        Class RulesReader - loads and executes shell scripts
                       from rule.d that translate actions to nft commands
 ruleserr.py           Exception class for RulesReader errors
 firewallreader.py     Class FirewallReader - reads firewall rule files
                       from incoming.d and outgoing.d directories
 firewallprocess.py    Class FirewallProcess - generates nft commands from
                       data loaded by FirewallReader
 listreader.py         Class ListReader - reads IP list files from
                       whitelist.d and blacklist.d directories
 listprocess.py        Class ListProcess - generates nft set commands
                       for IP addresses from the list directories
 netreader.py          Class NetReader - reads network CIDR ranges from
                       blacknets.d with JSON caching and deduplication
 nft.py                Main nftables interface facade - delegates to
                       nft_python.py or nft_shell.py based on config
 nft_shell.py          Shell-based nftables backend using subprocess
                       to call /usr/sbin/nft
 nft_python.py         Python-based nftables backend using libnftables
                       via the system nftables library, needs
                       python3-nftables installed.


Whitelist Management ('whitelist' action)
------------------------------------------

 whitelist.py          Scans wtmp for successful user logins and creates
                       whitelist entries with automatic expiry
 nftfw_utmp.py         ctypes interface to libc utmp/wtmp processing
 utmpconst.py          Constants for UTMP record types and file paths

Blacklist Management ('blacklist' action)
------------------------------------------

 blacklist.py          Main blacklist orchestration:
                       - Reads pattern files from patterns.d
                       - Scans logs for matching IPs
                       - Maintains blacklist database
                       - Creates/updates blacklist.d files
                       - Handles expiry and threshold-based blocking
 patternreader.py      Parses pattern files defining log files to scan,
                       ports, and regex patterns with __IP__ placeholder
 logreader.py          Incremental log scanning system with file rotation
                       detection and pattern matching
 whitelistcheck.py     IP validation against whitelist to prevent
                       blacklisting whitelisted addresses
 normaliseaddress.py   IP address validation, normalization, and filtering
                       (local addresses, test mode, IPv6 conversion)

Separate nftfw Programs
------------------------

nftfwadm.py            Admin utility front end providing 'save', 'restore',
                       and 'clean' commands for backup management
 fwcmds.py             Backup/restore commands:
                       - save: backup current ruleset
                       - restore: restore from backup
                       - clean: remove backup files

nftfwls.py             Database lister utility with formatted display:
                       - PrettyTable terminal output or HTML
                       - Filtering (active only vs all entries)
                       - Sorting options
                       - GeoIP2 integration

nftfwedit.py           Blacklist database editor with enhanced display:
                       - Information mode with GeoIP2 and DNSBL lookups
                       - add: database-only additions
                       - blacklist: create database entries and files
                       - delete: remove from database and files
                       - remove: remove files only (preserve database)
 nf_edit_dbfns.py      Database operation functions for nftfwedit
 nf_edit_print.py      Pretty printing with DNS, GeoIP2, and DNSBL data
 nf_edit_validate.py   User input validation functions

nftnetchk.py           Checks each IP in the blacklist database against
                       network ranges in the blacknets.d files.

nftfwan.py             Reads json data from the nftfables running on the system
                       reads the counters and prints a summary showing the
                       overall throughput of each of the main sections of
                       the firewall

External Service Integration
-----------------------------

dnsbl.py               DNS Blacklist (DNSBL) lookup support
                       (requires python3-dnspython, optional)
geoipcountry.py        GeoIP2 country lookup support
                       (requires geoip2 library, optional)

"""
