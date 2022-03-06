"""
Files in nftfw - and a description of what they do

PackageIndex.txt      this file
__init__.py	      amend the Python module lookup


Main nftfw application
----------------------

__main__.py	       Main application, deals with argument decode
		       and dispatch
config.py	       Class Config - supplies default config settings,
                       reads a config.ini file, supports overriding
		       the settings from the command line
		       Sets up logging
		       the object is passed into all modules
loggermanager.py       Manages the Python Logger modules so
                       output can be controlled to the terminal
                       and also the terminal
stdargs.py             Decodes -q -v and -o arguments
                       also used by nftfwadm

Utilities
--------

locker.py	       Provides an overall filesystem lock for the
                       various applications
sqdb.py		       Class SqDb - simple interface to sqlite3
fileposdb.py	       Derived from SqDb, FileposdB is interface to
                       the sqlite3 filepos table storing last seek positions
		       for log files
fwdb.py		       Derived from SqDb, FwDb is interface to sqlite3
                       providing an interface to the blacklist database
scheduler.py	       Provides locking and command sequencing for
                       both background commands run from cron, systemd or
                       incron and also for commands run from the
                       command line
stats.py               Compute durations and frequencies

Nftfw modules
-------------
'load' function:
fwmanage.py	       fw_manage manages creation and installation of nftables
 rulesreader.py	       Class RulesReader - reads rules from rules directory
                       rules translate actions into nft commands
 ruleserr.py	       Exception class for RulesReader
 firewallreader.py     Class FirewallReader - reads specification files
                       from the incoming and outgoing directories
 firewallprocess.py    Class FireWallProcess - generates nft commands from
                       data read by FirewallReader
 listreader.py	       Class ListReader - reads files from whitelist &
                       blacklist directories
 listprocess.py	       Class ListProcess - generates nft commands from
                       the two directories, generates nftable sets
                       with ip addresses
 netreader.py          Class NetReader - reads files from blacknets directory
                       validates entries and creates lists that can be used
                       in listprocess to output the sets.
 nft.py		       Interface for loading and reading nftables. Uses
                       either nft_python.py or nft_shell.py depending on
                       the setting of nft_select in config.ini.
 nft_shell.py          Original interface to nftables using the shell to
                       call /usr/sbin/nft to do the work.
 nft_python.py         Interface to nftables using an extended version
                       of the python nftables module.
 nftables.py           Edited version of the standard python library to
                       add in the missing calls that are needed for nftfw.

'whitelist' function
 whitelist.py	       Reads information from wtmp looking for
                       user logins, adds whitelist entries
                       to the directory when found.
                       Will automatically remove entries after
                       a set period
 nftfw_utmp.py	       Interface to libc utmp processing
                       I got fed up with waiting for the Debian
                       utmp package to be available for Python3
                       on Buster
 utmpconst.py	       Constants for the utmp interface

'blacklist' function
 blacklist.py	       Controls blacklisting, reads patterns
		       from patterns.d to establish files to scan and
		       how to scan them.
		       Using this information is maintains the
		       blacklist sqlite3 database, and writes files in
		       the blacklist directory
 patternreader.py      Parses pattern files, establishing log files to
		       scan and regexes to apply.
 logreader.py	       Uses patternreader output and manages file
		       scanning
 whitelistcheck.py     Checks whether addresses found in logs
                       are actually whitelisted, don't blacklist
                       whitelist addresses
 normaliseaddress.py   Validates IP addresses, does checking
                       to ignore local ones

Separate nftfw programs
-----------------------

nftfwadm.py            Front end for the nftfwadm command
		       'clean','save' & 'restore' functions
 fwcmds.py	       flush action: removes all nftables commands
                       cleans install directory
		       clean action: cleans install directory


nftfwls.py	       Provides a pretty print of the contents of the
		       blacklist database matching the entries in the
		       blacklist directory

nftfwedit.py           Prints data from the system, integrating
                       GeoIP2 lookups and DNSBL Lookups
                       Also provides cmdline interface to add, delete
                       and blacklist ip addresses

 nf_edit_dbfns.py      Main editing functions for nftfwedit
 nf_edit_print.py      Print function for nftfwedit
 nf_edit_validate.p    User input validate functions

dnsbl.py               DNS Blacklist lookup
geoipcountry.py        Geolocation interface

"""
