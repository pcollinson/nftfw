#!/usr/bin/env python3
"""Import settings from a Sympl or Symbiosis firewall system
into nftfw's control files.

The script compares the installations from Sympl/Symbiosis with that
of nftfw to decide what needs to be done. By default it will print
tables of results and will not create files unless requested to by
program argument.

Full installation will require root access.

The script has two parts which can be used together or independently.
Part 1 - creates nftfw versions of the incoming.d and outgoing.d
         directories, taking account of the rules in rule.d
	 that files in  these directories use to add commands to the firewall.
Part 2 - creates nftfw versions of the blacklist.d and whitelist.d
         directories. On installation into /etc/nftfw, the database
         used by nftfw to store blacklisted IP address information
         can be updated.
There are various options to the command, supply the command with
no options or use the -h or --help options to see them.

Installing files into /etc/nftfw could be disasterous on a live
system. The intention behind the implementation is to provide a
dry-run by default. (The $ on the lines below are there to indicate a
command to run).

To print this information:
$ import_to_nftfw.py

To print help for the options
$ import_to_nftfw.py --help

To see what import_to_nftfw will do only with firewall rules:
$ import_to_nftfw.py --rules

To see what import_to_nftfw will do only with blacklist.d and whitelist.d:
$ import_to_nftfw.py --lists

You can combine these (it will process rules first)
$ import_to_nftfw.py --rules --lists

To write test files on /tmp/import_nftfw, which it will create (or clean if it exists),
$ import_to_nftfw.py --rules --test

You can add --lists to do both
$ import_to_nftfw.py --rules --lists --test

To suppress information being printed,
--quiet stops setup information, --silent stops installation
and database update output
$ import_to_nftfw.py --rules --lists --test --quiet --silent

To install the final rules into /etc/nftfw quietly (note use of sudo)
$ sudo import_to_nftfw.py --rules --install --quiet

To install the final blacklist/whitelist data into /etc/nftfw (note
use of sudo) NB Be careful, this will update nftfw's firewall database
with any previously automatic blacklist entries. You only want to do
this once.
$ sudo import_to_nftfw.py --rules --install --quiet

To install the final blacklist/whitelist data into /etc/nftfw, and
update the blacklist database.
$ sudo import_to_nftfw.py --rules --install --update

To update the firewall database, if you've not done it and updated
the directories
$ sudo import_to_nftfw.py --lists --update

Combine full installation of /etc/nftfw (don't create testfiles)
$ sudo import_to_nftfw.py --rules --lists --install --update

Combine full installation of /etc/nftfw (don't create testfiles)
and sat nothing except for errors, hopefully none
$ sudo import_to_nftfw.py --rules --lists --install --update --quiet --silent

It's your responsibility to clean up /tmp/import_nftfw.

All the -- options above, have shortened versions with - and their initial
letter - so --rules can be -r.

"""

import sys
import argparse
import subprocess
from pathlib import Path
from config import Config
from configerr import ConfigError
from rules import ProcessRules
from lists import ProcessLists
from install import Installer

# pylint: disable=redefined-outer-name

def get_program_args():
    """ Get program arguments

    returns parsed arguments unless handled locally
    """

    desc = """Import Sympl or Symbiosis firewall control files into nftfw

Run the command with no arguments to get 'How to' type help.
"""

    ap = argparse.ArgumentParser(prog='import',
                                 description=desc
                                 )


    main = ap.add_argument_group(title='Main actions',
                                 description='One or both of these must be selected. \
                                 If neither are selected, will print how-to information. \
                                 Hint: pipe through less.')
    main.add_argument('-r', '--rules',
                      help='Process firewall rules in incoming.d and outgoing.d',
                      action='store_true')

    main.add_argument('-l', '--lists',
                      help='Process firewall lists in blacklist.d and whitelist.d',
                      action='store_true')

    disp = ap.add_argument_group(title='Disposition options',
                                 description='These are all optional.')

    disp.add_argument('-t', '--test',
                      help='Create test files in /tmp/import_to_nftfw, \
                      default is just to print information',
                      action='store_true')

    disp.add_argument('-i', '--install',
                      help="""Install result in /etc/nftfw.
                      Implies --testfiles but will delete them after running.
                      Only use this flag as a final step, it's a one way trip!""",
                      action='store_true')

    disp.add_argument('-u', '--update',
                      help="""Update nftfw firewall database from blacklist.d
                      Only used with --lists""",
                      action='store_true')

    disp.add_argument('-q', '--quiet',
                      help="""For --test and --install,
                      Don't print information about what it wants to do""",
                      action='store_true')

    disp.add_argument('-s', '--silent',
                      help="""For --test and --install,
                      Don't print out what directories and files are being installed,
                      and suppress output from database update.
                      """,
                      action='store_true')

    arguments = ap.parse_args()
    if not arguments.rules and not arguments.lists:
        print(__doc__)
        return None
    return arguments


def processrules(cf, is_quiet):
    """ Process rule files
    Called with cf and the quiet flag

    Returns {'incoming': ProcessRulesObject,
             'outgoing': ProcessRulesObject,
            }

"""

    out = {}
    for name in ('incoming', 'outgoing'):
        out[name] = ProcessRules(cf, name)
        if not is_quiet:
            out[name].print_records(f'{name} - {cf.outdirs["rules"][name]}')
    return out

def processlists(cf, is_quiet):
    """ Process rule files
    Called with cf and the quiet flag

    Returns {'blacklist': ProcessRulesObject,
             'whitelist': ProcessRulesObject,
            }

"""

    out = {}
    for name in ('blacklist', 'whitelist'):
        out[name] = ProcessLists(cf, name)
        if not is_quiet:
            out[name].print_records(f'{name} - {cf.outdirs["lists"][name]}')
    return out


def must_be_root(cf):
    """Check if running as root and die if not"""

    if not cf.am_i_root():
        print("Run the program as root")
        sys.exit(1)


def is_nftfw_path_running():
    """ Run external check script to find if the nftfw.path service is running

    Shell script exits with
    0 if nftfw.path is not running
    1 if nftfw.path is running
    2 if systemctl is not installed
    we just return that value
    """

    chk = subprocess.run(('/bin/sh', 'check_for_nftfw_path.sh'), stdout=subprocess.PIPE)
    return chk.returncode


if __name__ == '__main__':

    # pylint: disable=invalid-name

    args = get_program_args()
    if args is None:
        sys.exit(0)

    if not args.rules and not args.lists:
        print(__doc__)
        exit(0)

    # Get config
    try:
        cf = Config()
    except ConfigError as e:
        print(str(e))
        sys.exit(1)

    if not args.quiet:
        # Print what we've found
        print('Directories that will be used:')
        print(f"{cf.system_type} source directory: {str(cf.etcs['src'])}")
        print(f"Nftfw source & destination directory: {str(cf.etcs['nftfw'])}")
        print(f"Nftfw var lib directory: {str(cf.vars['nftfw'])}")
        print()

    if args.install or args.update:
        must_be_root(cf)

    # worry about automatic path watching
    sysctl = is_nftfw_path_running()
    if sysctl != 3:
        if sysctl == 1:
            if args.install or args.update:
                print(f"You need to run\n    sudo systemctl stop nftfw.path")
                print(f"Please do that and restart this command.\nAfter final import restart the service.")
                sys.exit(1)
            else:
                print(f"*** Warning: you need to run\nsudo systemctl stop nftfw.path\nbefore")
                print(f"Remember to restart the service after you've updated nftfw.")
                print()
                
    install = Installer(cf, args.silent)

    # we are doing rules
    if args.rules:
        ruleobjs = processrules(cf, args.quiet)
        if args.test:
            install.install_files(Path(cf.test_install), cf.outdirs['rules'], ruleobjs)
        if args.install:
            install.install_files(Path(cf.etcs['nftfw']), cf.outdirs['rules'], ruleobjs,
                                  uid=cf.etc_uid, gid=cf.etc_gid)

    if args.lists:
        listobjs = processlists(cf, args.quiet)
        if args.test:
            install.install_files(Path(cf.test_install), cf.outdirs['lists'], listobjs)
        if args.install:
            install.install_files(Path(cf.etcs['nftfw']), cf.outdirs['lists'], listobjs,
                                  uid=cf.etc_uid, gid=cf.etc_gid)
        if args.update:
            install.install_database(listobjs['blacklist'])
    sys.exit(0)
