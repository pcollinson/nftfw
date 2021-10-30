"""nftfw main module
usage: nftfw [-h] [-v] [-c CONFIG] [-q] [-d] [-x] [-f] [-p PATTERN] [-i]
             [-o OPTION]
             [action]

nftfw - firewall management system for nftables based on the Symbiosis firewall

positional arguments:
  action                load|whitelist|blacklist|tidy

optional arguments:
  -h, --help            show this help message and exit
  -v, --version         Show version
  -c CONFIG, --config CONFIG
                        Supply a configuration file overriding the built-in
                        file
  -q, --quiet           Suppress printing of errors, syslog output remains
                        active
  -d, --debug           Show information messages
  -x, --no-exec         Create and test rules, but don't install. Also applies
                        to blacklist
  -f, --full            Perform a full install, don't just update sets
  -p PATTERN, --pattern PATTERN
                        For blacklist, run using one pattern name
  -i, --info            Display current config settings and exit
  -o OPTION, --option OPTION
                        Specify comma separated list of option=value.
                        Overrides values from compiled values and config file.
                        Can be used several times

Optional commands:
    load       load firewall
    whitelist  load whitelist by scanning the system wtmp file, setting
               entries in the whitelist directory
    blacklist  load blacklist using files in the patterns directory
               to scan log files, automatically expire entries
               use -x to scan and print matches without storing any information
               use -p patternname to only process a specific pattern file
                usually for testing
    tidy       Tidy firewall database by removing entries that are older than
               a set number of days. Intended to be run from cron daily

"""
# Ini file for nftfw
#
# I want the modules here to appear in a package at some point
# so it will be in the search path for the world.
#
# It seems that the only way NOT to have to change the import code in every file
# is to meddle with the sys.path variable here
#
import sys
# check version of python
# this code has been tested on 3.6 and is really
# aimed at running on 3.7
assert sys.version_info >= (3, 6)
