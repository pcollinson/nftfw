"""nftfwadm - Admin tools for managing nftfw installation.

This module provides the command-line interface for nftfwadm, an administrative
utility for managing nftfw's nftables backup and restore functionality.

**Commands:**

save
    Saves the currently installed nftables settings to a backup file. This file
    is used for recovery by nftfw if problems occur during installation. The save
    command allows reverting to non-nftfw settings when testing the system.

restore
    Restores the saved nftables configuration from the backup file and replaces
    /etc/nftables.conf. This is useful for recovering from installation issues
    or reverting to a previous known-good state.

clean
    Deletes the backup file when it is no longer needed.

**Workflow:**

1. Parse command-line arguments including action and options
2. Create Config instance and optionally load custom ini file
3. Process standard arguments (-q, -v, -o) via nftfw_stdargs
4. Complete configuration setup (logging, paths)
5. Verify root permissions with am_i_root()
6. Pass action to Scheduler for execution

The Scheduler handles the actual implementation via fwcmds module functions
(fw_save, fw_restore, fw_clean) with proper locking and queueing.

**Related Modules:**
    - fwcmds: Implements save/restore/clean commands
    - nft_python/nft_shell: Backend implementations for nftables interaction
    - scheduler: Orchestrates command execution with locking

Example:
    Save current nftables configuration::

        $ nftfwadm save

    Restore from backup::

        $ nftfwadm restore

    Clean backup file::

        $ nftfwadm clean

    Use custom config file::

        $ nftfwadm -c /path/to/config.ini save

    Verbose output::

        $ nftfwadm -v save
"""
from __future__ import annotations

import sys
import argparse
from pathlib import Path

import pkg_resources

from .config import Config
from .scheduler import Scheduler
from .stdargs import nftfw_stdargs

def main() -> None:
    """Main entry point for nftfwadm command-line utility.

    Parses command-line arguments, initialises configuration, and executes
    the requested administrative action (save, restore, or clean) via the
    Scheduler.

    **Command-Line Options:**

    -c, --config PATH
        Supply a configuration file overriding the built-in file location

    -i, --info
        Display current config settings and exit without performing action

    -o, --option KEY=VALUE
        Specify configuration overrides as comma-separated KEY=VALUE pairs.
        Can be used multiple times to override compiled defaults and config file

    -q, --quiet
        Suppress printing of errors on console (syslog output remains active)

    -v, --verbose
        Show information messages during execution

    action
        Required action to perform: save, restore, or clean

    **Workflow:**

    1. Parse command-line arguments with argparse
    2. Create Config instance without completing setup (dosetup=False)
    3. Optionally load custom ini file from -c argument
    4. Read ini file and apply -o option overrides
    5. Process standard arguments (-q, -v, -o) via nftfw_stdargs
    6. Display config and exit if -i/--info specified
    7. Complete configuration setup (logging, paths)
    8. Verify root permissions (exits if not root)
    9. Create Scheduler and run the specified action
    10. Exit with success status

    Returns:
        None. Exits with code 0 on success, 1 on errors.

    Example:
        Called automatically when nftfwadm is run from command line::

            $ nftfwadm save
            $ nftfwadm -v restore
            $ nftfwadm -c /etc/nftfw/custom.ini clean
    """
    version = pkg_resources.require('nftfw')[0].version

    desc = 'Admin tools for managing nftfw installation'
    epilog = '\n'.join(["""Actions:
    save       Saves the currently installed nftables settings
               in a file, which is used for recovery by nftfw if problems
               happen with installation.

               If the file doesn't exist, the current settings are
               stored in the file before installation and then recovered
               when problems occur. The save option allows reverting
               back to non-nftfw settings when testing.

    restore    Restores the saved values in the nft settings and
               replaces /etc/nftables.conf.

    clean      Deletes backup file

    """, f'Version: {version}\n'])

    ap = argparse.ArgumentParser(prog='nftfwadm',
                                 formatter_class=argparse.RawDescriptionHelpFormatter,
                                 description=desc,
                                 epilog=epilog)
    ap.add_argument('-c', '--config',
                    help='Supply a configuration file overriding the built-in file')
    ap.add_argument('-i', '--info',
                    help='Display current config settings and exit',
                    action='store_true')
    ap.add_argument('-o', '--option',
                    help='Specify comma separated list of option=value.' \
                    + 'Overrides values from compiled values and config file. ' \
                    + 'Can be used several times',
                    action='append')
    ap.add_argument('-q', '--quiet',
                    help='Suppress printing of errors on console, syslog output remains active',
                    action='store_true')
    ap.add_argument('-v', '--verbose',
                    help='Show information messages', action='store_true')
    ap.add_argument('action', nargs='?',
                    help='Action to take', choices=['save', 'restore', 'clean'])
    args: argparse.Namespace = ap.parse_args()

    #
    # Sort out config
    # but don't initialise anything as yet
    #

    try:
        cf: Config = Config(dosetup=False)
    except AssertionError as e:
        print(f'Aborted: Configuration problem: {str(e)}')
        sys.exit(1)

    # allow change of config file
    if args.config:
        file = Path(args.config)
        if file.is_file():
            cf.set_ini_value_with_section('Locations', 'ini_file', str(file))
        else:
            print(f'Cannot find config file: {args.config}')
            sys.exit(1)

    # Load the ini file if there is one options can set new values
    # into the ini setup to override
    try:
        cf.readini()
    except AssertionError as e:
        print(f'Aborted: {str(e)}')
        sys.exit(1)

    # decode and action standard args
    nftfw_stdargs(cf, args)

    # list options and exit
    if args.info:
        print(repr(cf))
        sys.exit(0)

    # Check on actions
    if args.action not in ('clean', 'save', 'restore'):
        ap.print_help(sys.stderr)
        sys.exit(1)

    # Now set things up
    try:
        cf.setup()
    except AssertionError as e:
        print(f'Aborted: Configuration problem: {str(e)}')
        sys.exit(1)

    # no return if not true
    cf.am_i_root()

    sc: Scheduler = Scheduler(cf)
    sc.run(args.action)

if __name__ == '__main__':
    main()
    sys.exit(0)
