"""nftfw configuration class

This module provides the central configuration management system for nftfw,
handling configuration from multiple sources with a priority hierarchy:
compiled defaults → ini file → command-line arguments.

The Config class is passed into every nftfw component to convey system settings,
manage paths, and provide access to configuration values.

Configuration Sources:
    1. Compiled-in defaults (default_parser_settings)
    2. External ini file (typically /etc/nftfw/config.ini)
    3. Command-line argument overrides

Key Features:
    - Manages all system paths (config directories, working directories, databases)
    - Integrates with LoggerManager for logging configuration
    - Provides type-safe API for accessing configuration values
    - Supports both string and boolean configuration options
    - Includes path caching for performance

Example:
    Basic usage::

        from .config import Config

        # Initialize with automatic setup
        config = Config()

        # Access configuration values
        sysetc = config.etc_base
        build_path = config.varpath('build')

        # Change logging settings
        config.set_logger(loglevel='DEBUG', logprint=True)

    Deferred setup for testing::

        # Initialize without automatic setup
        config = Config(dosetup=False, localroot='/test/root')

        # Modify settings programmatically
        config.set_ini_value('loglevel', 'DEBUG')

        # Complete setup
        config.readini()
        config.setup()

See Also:
    - loggermanager.LoggerManager: Manages logging configuration
    - ConfigParser: Python's standard configuration file parser
"""
from __future__ import annotations

import os
import sys
import pwd
from functools import wraps
from pathlib import Path
from configparser import ConfigParser, ExtendedInterpolation
from configparser import Error as ConfigParserError
import logging
from typing import TYPE_CHECKING, Callable, Any, cast

from .loggermanager import LoggerManager

if TYPE_CHECKING:
    from typing import TypeVar
    F = TypeVar('F', bound=Callable[..., Any])

log = logging.getLogger('nftfw')

def cache(func: Callable[..., Path]) -> Callable[..., Path]:
    """Decorator to cache path lookup values.

    Caches the results of path lookup methods to avoid repeated filesystem
    operations and string manipulations. The cache key is based on the
    second argument (arg[1]), which is typically the name parameter.

    Args:
        func: A function that returns a Path object. Expected to be a method
            with signature (self, name: str) -> Path.

    Returns:
        A wrapped function with caching behaviour that returns Path objects.

    Example:
        @cache
        def varpath(self, name: str) -> Path:
            # Expensive path construction
            return Path(...) / name

    Note:
        The cache is stored as a closure variable and persists for the
        lifetime of the decorated function object. This is suitable for
        paths that don't change during program execution.
    """
    saved: dict[str, Path] = {}

    @wraps(func)
    def newfunc(*arg: Any) -> Path:
        if arg[1] in saved:
            return saved[arg[1]]
        result = func(*arg)
        saved[arg[1]] = result
        return result
    return newfunc

class Config:
    """Central configuration management for nftfw.

    This class manages all configuration settings for the nftfw firewall system,
    loading settings from compiled defaults, ini files, and command-line arguments.
    It provides a centralized API for accessing configuration values and manages
    system paths, logging configuration, and user/group ownership settings.

    The configuration is loaded in three stages:
        1. __init__(): Load default settings from default_parser_settings
        2. readini(): Read external config.ini file (if exists)
        3. setup(): Finalize settings and validate installation

    Attributes:
        parser: ConfigParser instance containing all configuration values
        logger_mgr: LoggerManager instance for logging configuration
        inireverse: Reverse mapping of option names to section names

        # Logging settings (from [Logging] section)
        logfmt: Format string for log messages
        loglevel: Log level name (CRITICAL, ERROR, WARNING, INFO, DEBUG)
        logfacility: Syslog facility name
        logprint: Whether to print logs to console
        logsyslog: Whether to send logs to syslog

        # Ownership settings (determined from sysetc directory)
        fileuid: UID for created files (default: root/0)
        filegid: GID for created files (default: root/0)
        execuid: UID for executing shell scripts (default: nobody)
        execgid: GID for executing shell scripts (default: nobody)

        # Runtime flags (set by command-line arguments)
        create_build_only: Test mode - build but don't install (-x flag)
        force_full_install: Force full firewall install (-f flag)
        selected_pattern_file: Pattern file selected with -p option
        selected_pattern_is_test: Whether selected pattern is a test file

        # Module integration attributes
        rulesreader: Reference to RulesReader instance (set by firewallreader.py)
        nft_select: Selected nftables interface ('python' or 'shell')
        editargs: Arguments for nftfwedit (dict)

        # IPv6 settings
        default_ipv6_mask: Default subnet mask for IPv6 addresses (default: 112)

    Configuration Sections:
        [Locations]: Directory paths (sysetc, sysvar, ini_file, nftables_conf)
        [Rules]: Default actions (incoming, outgoing, whitelist, blacklist, blacknets)
        [Logging]: Logging configuration (logfmt, loglevel, logfacility, etc.)
        [Nft]: nftables settings (counters, logging prefixes, set auto-merge)
        [Whitelist]: Whitelist settings (wtmp_file, whitelist_expiry)
        [Blacklist]: Blacklist thresholds and expiry settings
        [Nftables]: nftables interface selection (nft_select)
        [Nftfwls]: Output formatting for nftfwls command
        [Nftfwedit]: DNSBL lookup configuration

    Example:
        Standard usage::

            config = Config()
            build_path = config.varpath('build')
            blacklist_path = config.etcpath('blacklist')

        Deferred setup for testing::

            config = Config(dosetup=False, localroot='/test/root')
            config.set_ini_value('loglevel', 'DEBUG')
            config.readini()
            config.setup()

    Note:
        The Config instance is typically created once and passed to all
        nftfw components. Callers should trap AssertionError exceptions
        which are raised for configuration errors and missing directories.

    See Also:
        loggermanager.LoggerManager: Manages logging configuration
        ConfigParser: Python's configuration file parser
    """

    # pylint: disable=too-many-instance-attributes, too-many-lines
    # This is a config class and needs loads

    # Default settings
    # These values are all imported into
    # this class
    default_parser_settings: str = """
#
# Ini style file that can be used
# to override compiled in settings
# for nftfw.
#
#
# Sections are important
# All set to DEFAULT for the compiled in settings
[Locations]
#
#  Various directories are supplied by config
#  and it's desirable to add a 'reasonably static'
#  root. All directories are then automatically
#  prefixed by the root. Values from the config.ini
#  file should be specified relative to the root.
#  Set to empty here, so we can look for /etc/nftfw
#  and /usr/local/etc/nftfw to find where things
#  are installed
root
#  system locations used by nftfw
#  NB sysetc location cannot be changed unless
#  the ini file is used as the -c option
#  to nftfw main scripts
sysetc = ${root}/etc/nftfw
sysvar = ${root}/var/lib/nftfw

#  Default ini file - not tailorable
#  chickens and eggs are the usual explanation
ini_file = ${sysetc}/config.ini

#  Location of system nftables.conf
#  Should be /etc/nftables.conf for production.
#  But because we don't want to kill people's
#  systems when they first install nftfw
#  This will default to {sysexec}/nftables.conf
#  and installers will be asked to change it.
#  nftables_conf = ${sysetc}/nftables.conf
nftables_conf = ${sysetc}/nftables.conf

#  Where the initial nft setup for the firewall is found
nftfw_init = ${sysetc}/nftfw_init.nft

[Rules]
#   Default rules for incoming and outgoing
#   Possible to use 'drop' for reject here
incoming = accept
outgoing = reject
whitelist = accept
blacklist = reject
blacknets = drop

[Logging]
#  System Logging constants
#
#  Format of log statements
logfmt = nftfw[%(process)d]: %(message)s
#  what level are we logging at
#  needs to be a level name not a value
#  CRITICAL, ERROR, WARNING, INFO, DEBUG
#  Use ERROR for production
loglevel = INFO
#  what facility are we using
#  needs to be a facility name not a value
logfacility = daemon
#  Print and syslog options default to True
#  set to False to inhibit log printing
#  NB this value is initially set to
#  False when the program is not talking to
#  a terminal
logprint = True
#  set to False to inhibit syslog use
logsyslog = True

[Nft]
#  Nftables counters and logging
#  do we want counters?
incoming_counter = True
outgoing_counter = True
blacklist_counter = True
whitelist_counter = True
blacknets_counter = True

#  do we want nftables logging?
#  this adds a different prefix for each of the tables
#  when logged
#  use empty value to mean none
incoming_logging
outgoing_logging
blacklist_logging = Blacklist
whitelist_logging
blacknets_logging

# The three variables below control the type of sets automatically
# generated for blacklist, blacknets and whitelist tables. When true,
# nftfw uses auto_merged, interval sets for the sets it makes. This
# set type automatically create single entries containing an address
# range for adjacent IP addresses. The feature is desirable because it
# reduces the number of matches.
#
# However, at present, the auto-merged, interval sets can cause the
# nft program to fail, flagging an error. There is a bug causing
# nft to succeed in loading the set when a full install is performed
# but failing when attempting a reload.
#
# This bug has been fixed in recent nftables coding. I've had no
# problem usinf this feature, and it's often a win for all these tables.
blacklist_set_auto_merge = False
whitelist_set_auto_merge = False
blacknets_set_auto_merge = False

[Whitelist]
#
#  Whitelist constants
#  Wtmp file to scan, empty to use the system
#  default. Set wtmp_file=utmp to use the system default
#  utmp file, otherwise set to a file
wtmp_file

#  Days after which automatically generated
#  whitelist entries are expired from the system
whitelist_expiry = 10

[Blacklist]
# Constants to manage blacklisting
# these depend on the matchcount value
# found from the logreader script
# NB Symbiosis had multiple records
# for each ip. This system only has one record
# but records timestamps. Expiry uses the
# complete record of activity from the ip
#
# Value in matchcount after which
# an ip is blocked using the ports in
# the rule (Symbiosis used 2)
block_after = 10
#
# Value in matchcount after which
# an ip is blocked using all ports
block_all_after = 100
#
# These depend on the time of last incident
#
# Number of days after which blacklisted ips
# should be expired. Symbiosis used 2
expire_after = 10
#
# Database clean
# remove ip from the database where there has been
# no error posted for more than these number of days
clean_before = 90
#
# Database clean
# remove ip from the database when there has been no
# error posted for more than thses number of days.
# The database will include values for incident count
# and matchcount depending on the settings of the variables
# below. These are likely to be low numbers.
# The clean can be turned off by setting this value to zero.
# It's being distributed as zero, for backwards compatibility.
clean_by_count = 0
# numbers included in the database lookup for the clean_by_count
# editing method. The test is that the particular stored value
# must be less than or equal to the value supplied here.
# Either of these values may be zero, and if so, this test is
# not included in the database lookup
incidents_le = 1
matchct_le = 3

# 'nftfw blacklist' will check whether the IP addresses
# in the database that should be active are actually present
# in the blacklist directory _blacklist.d_. 'Should be active'
# means that the addresses have not been automatically expired.
# 'nftfw' is largely event driven, but events get missed. So
# on the basis that if stuff can happen, it will, this code
# will recover the correct state of the blacklist directory.
# It seems overkill to call this every time the blacklist scanner
# runs, so it is executed when number of runs of the scanner
# is greater than the value of this variable. The default is
# to run the blacklist scanner 96 times a day, so 50 seems
# are reasonable way to run the recovery code once a day. Set
# this to zero  to turn this feature off.
sync_check = 50

# Supply default ipv6 mask. IPv6 addresses are
# automatically masked to select a device. This was originally
# /64 which is very aggressive and blocked too many addresses.
# Following the lead from a recent sympl update this is now
# changed to /112, and parameterised here.
default_ipv6_mask = 112

[Nftables]
# Allow selection of method used to load/unload nftables
#  Select from
#     shell - the original interface that uses /usr/sbin/nft
#     python - uses a python library
nft_select = python

[Nftfwls]
# Allow local selection for date formats in nftfwls
# and nftfwedit print option
# seconds are not that relevant
# dd-mm-YYYY HH:MM
date_fmt = %d-%m-%Y %H:%M
#
# Replaces comma in the pattern listing by
# newline and a space to reduce output width
pattern_split = No

[Nftfwedit]
# Supply DNSBL lookup names and lookup addresses
;SpamHaus=zen.spamhaus.org
;Barracuda=b.barracudacentral.org
;SpamCop=bl.spamcop.net

"""

    # Where to look for root files
    # list of prefixes
    # '' is basically /
    rootlist: tuple[str, ...] = ('', '/usr/local')

    # Directories we expect to find in sysetc
    etc_dir: dict[str, str] = {'incoming':  'incoming.d',
                                'outgoing':  'outgoing.d',
                                'whitelist': 'whitelist.d',
                                'blacklist': 'blacklist.d',
                                'blacknets': 'blacknets.d',
                                'patterns':  'patterns.d',
                                'rule':      'rule.d',
                                'local':     'local.d'}

    # Directories we expect to find in the sysvar
    var_dir: dict[str, str] = {'build': 'build.d',
                                'install': 'install.d',
                                'test': 'test.d'}

    # Files we expect to find in the sysvar
    var_file: dict[str, str] = {'firewall' : 'firewall.db',
                                 'filepos'  : 'filepos.db',
                                 'backup'   : 'nftables.backup',
                                 'lastutmp' : 'whitelist_scan',
                                 'missingsync' : 'blacklist_missing_check',
                                 'blacknets_cache': 'blacknets_cache.json'}

    #   Values obtained from nftfw command line
    #
    #   if true create and test build files
    #   but don't install them (-x flag)
    #   Also used in blacklist to mean run test
    create_build_only: bool = False
    #
    #   if true force a full install of firewall
    #   (-f flag)
    force_full_install: bool = False

    #
    #   pattern name selected by the -p option
    #
    selected_pattern_file: str | None = None
    #
    #   flag to say that the single pattern file
    #   is a test file, set when the pattern file is read
    selected_pattern_is_test: bool = False

    #   Some modules poke values into here to allow global access.
    #   These are documented here
    #
    #   Used by firewallreader.py
    rulesreader: Any = None

    #   Value of nft_select
    nft_select: str | None = None

    #   Used by nftfwedit.py to pass args through the scheduler
    editargs: dict[str, Any] = {}

    #   Ini file support
    #   These are attributes we expect to find in the ini file
    #   Used to check on names for the -o option
    #   and also for deciding on type of ini variables
    ini_string_change: tuple[str, ...] = (
        'sysvar',
        'nftables_conf', 'nftfw_init',
        'incoming', 'outgoing', 'whitelist',
        'blacklist', 'blacknets',
        'logfmt', 'loglevel',
        'logfacility', 'incoming_logging',
        'outgoing_logging', 'blacklist_logging',
        'whitelist_logging', 'blacknets_logging',
        'whitelist_expiry', 'wtmp_file',
        'block_after', 'block_all_after',
        'expire_after', 'clean_before',
        'clean_by_count',
        'incidents_le','matchct_le',
        'default_ipv6_mask', 'date_fmt',
        'nft_select')

    ini_boolean_change: tuple[str, ...] = (
        'logprint', 'logsyslog',
        'incoming_counter', 'outgoing_counter',
        'blacklist_counter', 'whitelist_counter',
        'blacknets_counter',
        'blacklist_set_auto_merge',
        'whitelist_set_auto_merge',
        'blacknets_set_auto_merge',
        'pattern_split')

    def __init__(self, dosetup: bool = True, localroot: str | None = None) -> None:
        """Initialize Config instance and optionally complete setup.

        Creates a ConfigParser instance, loads default settings, determines
        the installation root, and optionally reads the ini file and completes
        setup. The initialisation process is split into three stages to allow
        for customization between stages.

        Initialization stages:
            1. __init__(): Load default settings and determine root
            2. readini(): Read external config.ini file (optional)
            3. setup(): Validate installation and finalize settings

        Args:
            dosetup: If True, automatically calls readini() and setup().
                If False, caller must manually call these methods. Default: True.
            localroot: Override root directory for testing. When provided,
                skips automatic root detection. Typically set to '.' for tests.
                Default: None (auto-detect from / or /usr/local).

        Raises:
            AssertionError: If configuration directories are missing or invalid.
                Callers should trap this exception for clean error handling.

        Example:
            Automatic setup::

                config = Config()  # Calls readini() and setup() automatically

            Manual setup for customization::

                config = Config(dosetup=False)
                config.set_ini_value('loglevel', 'DEBUG')
                config.readini()
                config.setup()

            Testing with local root::

                config = Config(dosetup=False, localroot='/tmp/test')
                config.readini()
                config.setup()

        Note:
            Sets umask to 0o022 to ensure created files have rw-r--r-- permissions.
            Disables console logging (logprint) if not connected to a terminal.
        """
        # establish parser and load default values
        self.parser: ConfigParser = ConfigParser(allow_no_value=True,
                                                   strict=False,
                                                   interpolation=ExtendedInterpolation())
        self.parser.read_string(self.default_parser_settings)

        # files we may create need to be rw-r--r--
        # once upon a time we all spoke octal
        os.umask(0o022)

        # turn off printing by default unless talking to a terminal
        # but can be overridden from config files and arguments
        if not sys.stdout.isatty():
            self.set_ini_value_with_section('Logging', 'logprint', False)

        # work out if we are based in / or /usr/local
        # set root in ini to affect paths
        if localroot is None:
            self._establishroot()
        else:
            # we are testing and need not to look
            # on the system, testing will pass in '.'
            self.parser.set('Locations', 'root', localroot)

        # used for ini lookup reverse mapping
        self.inireverse: dict[str, str] = {}

        # Setup code doesn't need to use the logging system
        # but this allows that if needed
        logvars = self.get_ini_values_by_section('Logging')
        # installing this could be a simple loop but let's stop pylint complaining
        self.logfmt: str = cast(str, logvars['logfmt'])
        self.loglevel: str = cast(str, logvars['loglevel'])
        self.logfacility: str = cast(str, logvars['logfacility'])
        self.logprint: bool = cast(bool, logvars['logprint'])
        self.logsyslog: bool = cast(bool, logvars['logsyslog'])

        # these are used in chownpath
        # see chownpath
        # default to root:root
        self.fileuid: int = 0
        self.filegid: int = 0

        # These are used in rulesreader to demote the shell script
        # execution away from root
        self.execuid: int = 0
        self.execgid: int = 0

        # default ipv6 mask
        # used in normalise.pl
        self.default_ipv6_mask: int = 112

        # now setup loggermanager
        self.logger_mgr: LoggerManager = LoggerManager(self, log)

        # if dosetup is false then
        # the caller has to do these
        if dosetup:
            self.readini()
            self.setup()

    def _establishroot(self) -> None:
        """Look on system to find the root for the nftfw files.

        Searches through the rootlist ('' and '/usr/local') to find where
        nftfw is installed by checking for the existence of the sysetc
        directory. Sets the 'root' variable in the parser to establish
        paths for all other location variables.

        Raises:
            AssertionError: If sysetc directory is not found in any root location,
                or if the found path is not a directory.

        Note:
            This method is only called when localroot is not provided to __init__.
            It automatically detects whether nftfw is installed in / or /usr/local.
        """
        rootsearch = self.rootlist
        root = self.parser.get('Locations', 'root')
        # set to none in the initial definitions
        if root is None:
            for r in rootsearch:
                self.parser.set('Locations', 'root', r)
                sysetc = self.parser.get('Locations', 'sysetc')
                psysetc = Path(sysetc)
                if psysetc.exists():
                    assert psysetc.is_dir(), f'{psysetc} is not a directory'
                    return
            assert False, 'Cannot find etc/nftfw directory'

        # safety code - shouldn't be called
        self.parser.set('Locations', 'root', '')

    def readini(self) -> None:
        """Read the external ini file if it exists.

        Loads configuration from the ini file specified in the Locations section
        (typically /etc/nftfw/config.ini). If the file doesn't exist, this method
        returns silently without error. Configuration values from the ini file
        override the compiled-in defaults.

        Also disables console logging (logprint) if not connected to a terminal,
        unless explicitly overridden in the ini file or by command-line arguments.

        Raises:
            AssertionError: If the ini file has syntax errors.

        Note:
            This method is idempotent and safe to call multiple times.
            It's acceptable for the ini file to not exist.
        """
        errors = []
        try:
            ini_file = self.parser.get('Locations', 'ini_file')
            # it's OK not to have an ini_file
            if not os.path.isfile(ini_file):
                return
            self.parser.read(ini_file)
        except ConfigParserError as e:
            errors.append(str(e).replace("\n", '; '))

        assert not errors, f'config.ini syntax errors: {" ".join(errors)}'

        # turn off printing by default unless talking to a terminal
        # but can be overridden from config files and arguments
        if not sys.stdout.isatty():
            self.set_ini_value_with_section('Logging', 'logprint', False)

    def setup(self) -> None:
        """Establish final settings and validate installation.

        Completes the configuration setup by:
        1. Updating logging configuration via LoggerManager
        2. Determining file ownership (UID/GID) from sysetc directory
        3. Setting execution UID/GID for shell script execution
        4. Validating nft_select setting ('python' or 'shell')
        5. Loading IPv6 mask setting
        6. Checking that all required directories exist

        Raises:
            AssertionError: If required directories/files are missing or
                nft_select has an invalid value.
            SystemExit: If 'nobody' user doesn't exist when needed for
                non-root execution.

        Note:
            This method must be called after readini() to finalize configuration.
            For root-owned installations, shell scripts execute as 'nobody' for
            security. For non-root installations, scripts execute as the owner.
        """
        # update our copies for Logging
        logvars = self.get_ini_values_by_section('Logging')
        for k, v in logvars.items():
            setattr(self, k, v)
        self.logger_mgr.setup()

        # Get owner of the sysetc directory
        # we know it exists
        dirname = self.parser.get('Locations', 'sysetc')
        dirpath = Path(dirname)
        assert dirpath.is_dir(), \
            f'Missing configuration directory (sysetc): {dirname}'
        dirstat = dirpath.stat()
        self.fileuid = dirstat.st_uid
        self.filegid = dirstat.st_gid
        # establish exec values
        if self.fileuid == 0 \
           and self.filegid == 0:
            # get uid/gid for 'nobody'
            try:
                nobody = pwd.getpwnam('nobody')
            except KeyError:
                err = ( "We need to find a non-root user, and there is no 'nobody'\n"
                        "account on this system. As a work-around use\n"
                        "   sudo dpkg-reconfigure nftfw\n"
                        "and set the user not to be root."
                      )
                print(err)
                sys.exit(1)
            self.execuid = nobody.pw_uid
            self.execgid = nobody.pw_gid
        else:
            self.execuid = self.fileuid
            self.execgid = self.filegid

        # check that nft_select is either 'python' or 'shell'
        select = self.parser.get('Nftables', 'nft_select')
        if select not in ('python', 'shell'):
            log.critical("Problem in config.ini: nft_select should be 'python' or 'shell'.")
            sys.exit(1)
        self.nft_select = select

        # set ipv6 mask
        ma = self.parser.get('Blacklist', 'default_ipv6_mask')
        self.default_ipv6_mask = int(ma)

        # Finally check on the installation
        self._check_installation()

    def _check_installation(self) -> None:
        """Check that all required control directories and files exist.

        Validates the nftfw installation by checking for:
        - Required sysetc subdirectories (incoming.d, outgoing.d, patterns.d, rule.d)
        - nftfw_init.nft file
        - sysvar directory and its subdirectories (build.d, install.d, test.d)

        Raises:
            AssertionError: If any required directories or files are missing.
                The error message includes a list of all missing paths.

        Note:
            This method is called automatically by setup() to ensure a valid
            installation before the system attempts to operate.
        """
        missing = []
        # sysetc is known to exist
        # but we are not sure of it's contents
        for name in ('incoming', 'outgoing', 'patterns', 'rule'):
            path = self.etcpath(name)
            if not path.is_dir():
                missing.append(str(path))

        # check on the nftfw_init.nft file
        if not self.nftfw_init.exists():
            missing.append(str(self.nftfw_init))

        # Now worry about the var directories
        p = self.get_ini_value_from_section('Locations', 'sysvar')
        sysvar = Path(cast(str, p))
        if not sysvar.is_dir():
            missing.append(str(sysvar))
        else:
            for name,dirname in self.var_dir.items():
                dir_path = sysvar / dirname
                if not dir_path.is_dir():
                    missing.append(str(dir_path))

        # log list is not empty
        assert not missing, f'Missing configuration directories/files: {" ".join(missing)}'

    def set_logger(self,
                   logprint: bool | None = None,
                   logsyslog: bool | None = None,
                   loglevel: str | None = None) -> None:
        """Set logger values and update logging configuration.

        Updates logging settings and reconfigures the LoggerManager.
        This method is typically called from command-line processing to
        handle the -q (quiet) and -v (verbose) flags.

        Args:
            logprint: If provided, enables/disables console logging.
                Typically set to False for -q flag. Default: None (no change).
            logsyslog: If provided, enables/disables syslog logging.
                Default: None (no change).
            loglevel: If provided, sets the log level name. Valid values are
                'CRITICAL', 'ERROR', 'WARNING', 'INFO', or 'DEBUG'.
                Typically set to 'INFO' for -v flag. Default: None (no change).

        Example:
            # Make logging quiet (disable console output)
            config.set_logger(logprint=False)

            # Make logging verbose
            config.set_logger(loglevel='INFO')

            # Disable all logging
            config.set_logger(logprint=False, logsyslog=False)

        Note:
            Changes are immediately applied by calling logger_mgr.setup().
            Values are stored both as instance attributes and in the parser.
        """
        # loggermanager uses cf values
        if logprint is not None:
            self.logprint = logprint
            self.set_ini_value_with_section('Logging', 'logprint', logprint)
        if logsyslog is not None:
            self.logsyslog = logsyslog
            self.set_ini_value_with_section('Logging', 'logsyslog', logsyslog)
        if loglevel is not None:
            self.loglevel = loglevel
            self.set_ini_value_with_section('Logging', 'loglevel', loglevel)
        self.logger_mgr.setup()

    #
    # Ini file apis
    #
    def set_ini_value_with_section(self,
                                     section: str,
                                     option: str,
                                     value: str | bool) -> None:
        """Set an ini value in a specific section.

        Updates a configuration value in the parser. Boolean values are
        automatically converted to string representation ('True'/'False')
        as required by ConfigParser.

        Args:
            section: Section name (e.g., 'Logging', 'Locations', 'Blacklist').
            option: Option name within the section (e.g., 'loglevel', 'sysetc').
            value: Value to set. If the option is in ini_boolean_change,
                boolean values are converted to 'True'/'False' strings.

        Example:
            config.set_ini_value_with_section('Logging', 'loglevel', 'DEBUG')
            config.set_ini_value_with_section('Logging', 'logprint', True)

        Note:
            This method directly modifies the parser. Changes may require
            calling logger_mgr.setup() or other setup methods to take effect.
        """
        str_value: str
        if option in self.ini_boolean_change:
            str_value = 'True' if value else 'False'
        else:
            str_value = cast(str, value)
        self.parser.set(section, option, str_value)

    def set_ini_value(self, option: str, value: str | bool) -> None:
        """Set an ini value without knowing its section.

        Convenience method that automatically determines the section for
        an option by using a reverse index. Creates the reverse index on
        first use.

        Args:
            option: Option name to set (e.g., 'loglevel', 'sysetc').
            value: Value to set. Boolean values are automatically converted
                to string representation if the option is boolean-valued.

        Example:
            config.set_ini_value('loglevel', 'DEBUG')
            config.set_ini_value('logprint', False)

        Note:
            If the option is not found in any section, an error is logged.
            The reverse index (inireverse) is built lazily on first call.

        See Also:
            set_ini_value_with_section: Direct method when section is known.
        """
        if not any(self.inireverse):
            self._make_inireverse()
        if option in self.inireverse:
            self.set_ini_value_with_section(self.inireverse[option], option, value)
        else:
            log.error('Cannot find option %s to set', option)

    def get_ini_value_from_section(self, section: str, option: str) -> str | bool:
        """Get a configuration value from a specific section.

        Retrieves a value from the parser and automatically converts boolean
        options to Python bool values.

        Args:
            section: Section name (e.g., 'Logging', 'Locations').
            option: Option name within the section.

        Returns:
            The configuration value. Returns bool for options in
            ini_boolean_change, str otherwise. Integer values are
            returned as strings and must be converted by the caller.

        Example:
            loglevel = config.get_ini_value_from_section('Logging', 'loglevel')
            sysetc = config.get_ini_value_from_section('Locations', 'sysetc')
            logprint = config.get_ini_value_from_section('Logging', 'logprint')

        Note:
            Boolean options are automatically detected and converted to bool.
            Numeric options remain as strings and require int() conversion.
        """
        str_value = self.parser.get(section, option)
        if option in self.ini_boolean_change:
            return str_value == 'True'
        return str_value

    def get_ini_values_by_section(self, section: str) -> dict[str, str | bool]:
        """Return all configuration values in a section.

        Retrieves all options from a section as a dictionary, automatically
        converting boolean options to Python bool values.

        Args:
            section: Section name (e.g., 'Logging', 'Locations', 'Blacklist').

        Returns:
            Dictionary mapping option names to values. Boolean options are
            returned as bool, all others as str.

        Example:
            logvars = config.get_ini_values_by_section('Logging')
            # logvars = {'logfmt': '...', 'loglevel': 'INFO', 'logprint': True, ...}

        Note:
            This is useful for bulk-loading configuration sections.
            Boolean conversion is applied automatically based on ini_boolean_change.
        """
        out: dict[str, str | bool] = {}
        for k, v in self.parser[section].items():
            if k in self.ini_boolean_change:
                out[k] = v == 'True'
            else:
                out[k] = v
        return out

    def _make_inireverse(self) -> None:
        """Build reverse index mapping option names to section names.

        Creates a dictionary that maps each configuration option to its
        section name, enabling set_ini_value() to work without knowing
        the section in advance.

        Sets:
            self.inireverse: Dict mapping option names to section names.

        Example:
            After calling this method:
            inireverse = {'loglevel': 'Logging', 'sysetc': 'Locations', ...}

        Note:
            This method is called automatically by set_ini_value() on first use.
            The index includes all options from all sections in the parser.
        """
        out = {}
        sects = self.parser.sections()
        for s in sects:
            for o in self.parser[s]:
                out[o] = s
        self.inireverse = out

    def get_ini_changed_values(self) -> str:
        """Compare current configuration with defaults and return differences.

        Builds a representation of configuration values that differ from the
        compiled-in defaults. This is useful for generating minimal config.ini
        files showing only customized settings.

        Returns:
            String representation of changed configuration values in INI format.
            Includes sections and options that differ from defaults, plus any
            unexpected sections/options that should be deleted.

        Example:
            Output format::

                [Logging]
                loglevel = DEBUG
                [Blacklist]
                block_after = 5
                # Delete section Unexpected from config.ini

        Note:
            The 'root' option is excluded from comparison.
            Terminal detection (logprint) is handled specially to avoid
            false positives when running non-interactively.
        """
        # Strategy - get a new empty parser object
        # from default settings
        # Fix up programmed changes
        # cycle through removing values that are
        # the same
        # Remove any empty sections
        # Return what's left as a repr

        base = ConfigParser(allow_no_value=True,
                            strict=False,
                            interpolation=ExtendedInterpolation())
        base.read_string(self.default_parser_settings)

        # remove root
        base.remove_option('Locations', 'root')
        self.parser.remove_option('Locations', 'root')

        # fix up initial logging value
        # so it gives the same result when not a tty
        if not sys.stdout.isatty():
            base.set('Logging', 'logprint', 'False')

        # now scan the base and compare with installed values
        sects = self.parser.sections()
        # Information found that should not be there
        should_delete = []
        for sect in sects:
            # section not in base
            if not base.has_section(sect):
                e = f"# Delete section {sect} from config.ini"
                should_delete.append(e)
                continue

            # scan through parser
            # insert any options that don't exist into base
            # or compare and remove identical values
            for opt in self.parser[sect]:
                if not base.has_option(sect, opt):
                    curr_val = self.parser.get(sect, opt, raw=True)
                    base.set(sect, opt, curr_val)
                else:
                    base_val = base.get(sect, opt, raw=True)
                    curr_val = self.parser.get(sect, opt, raw=True)
                    if base_val == curr_val:
                        base.remove_option(sect, opt)
                    else:
                        base.set(sect, opt, curr_val)

            # remove empty sections
            if not any(base.items(sect, raw=True)):
                base.remove_section(sect)

        # prepare output
        out = self.config_settings(base)
        if any(should_delete):
            out += "\n" + "\n".join(should_delete)
        return out

    @staticmethod
    def am_i_root() -> None:
        """Verify the process is running as root (UID 0).

        Checks the effective user ID and exits with an error message if not
        running as root. The error message is printed to console if running
        interactively, or logged via syslog otherwise.

        Raises:
            SystemExit: Always exits with code 1 if not running as root.

        Example:
            Config.am_i_root()  # Will exit if not root

        Note:
            This is a static method and doesn't require a Config instance.
            Most nftfw operations require root privileges to manage iptables/nftables.
        """
        if os.geteuid() != 0:
            if sys.stdout.isatty():
                print("Run the program as root")
            else:
                log.critical("Run the program as root")
            sys.exit(1)

    def chownpath(self, path: str | Path) -> None:
        """Set file ownership to match the sysetc directory owner.

        Changes the owner and group of a file to match the determined
        fileuid and filegid. Does nothing if running as root/root (the
        typical production configuration).

        Args:
            path: Path to the file whose ownership should be changed.
                Can be string or Path object.

        Example:
            config.chownpath('/var/lib/nftfw/firewall.db')

        Note:
            This ensures that files created by nftfw have consistent
            ownership with the configuration directory. For root-owned
            installations, this is a no-op.
        """
        if self.fileuid == 0 \
           and self.filegid == 0:
            return
        os.chown(path, self.fileuid, self.filegid)

    def config_settings(self, parser: ConfigParser) -> str:
        """Return configuration settings as formatted string.

        Converts a ConfigParser instance to a human-readable string
        representation showing all sections and their options.

        Args:
            parser: ConfigParser instance to format.

        Returns:
            Multi-line string with INI-style formatting showing all
            configuration sections and values.

        Example:
            Output format::

                [Logging]
                logfmt = nftfw[%(process)d]: %(message)s
                loglevel = INFO
                logprint = True

        Note:
            Boolean values are shown as True/False.
            Options with None values are shown without '= value'.
        """
        out = []
        sects = parser.sections()
        for s in sects:
            out.append('['+s+']')
            for o in parser[s]:
                if o in self.ini_boolean_change:
                    bool_val = parser.getboolean(s, o)
                    out.append(f'{o} = {str(bool_val)}')
                else:
                    str_val = parser.get(s, o, raw=True)
                    if str_val is None:
                        out.append(o)
                    else:
                        out.append(f'{o} = {str_val}')
        return "\n".join(out)

    def __repr__(self) -> str:
        """Return string representation of current configuration.

        Returns:
            Multi-line string showing all configuration sections and values
            in INI format.

        Example:
            print(config)  # Shows all configuration values
        """
        return self.config_settings(self.parser)

    #
    # Directory and file location API
    #
    @cache
    def varpath(self, name: str) -> Path:
        """Get full path to a directory in nftfw's var directory.

        Returns the path to working directories where nftfw stores databases,
        build files, and installed configurations. Automatically switches from
        'build' to 'test' directory when in test mode (create_build_only=True).

        Args:
            name: Directory name. Must be a key in var_dir:
                'build', 'install', or 'test'.

        Returns:
            Path object pointing to the requested directory
            (e.g., /var/lib/nftfw/build.d).

        Raises:
            AssertionError: If name is not in var_dir.

        Example:
            build_path = config.varpath('build')
            install_path = config.varpath('install')

        Note:
            Results are cached for performance. When create_build_only is True,
            requesting 'build' automatically returns the 'test' directory instead.
        """
        p = self.get_ini_value_from_section('Locations', 'sysvar')
        base = Path(cast(str, p))
        # switch to test if testing
        if name == 'build' \
           and self.create_build_only:
            name = 'test'
        assert name in self.var_dir, f'{name} not in var_dir'
        dir_path = base / self.var_dir[name]
        return dir_path

    @cache
    def varfilepath(self, name: str) -> Path:
        """Get full path to a file in nftfw's var directory.

        Returns the path to working files such as databases and backup files
        stored in the sysvar directory.

        Args:
            name: File identifier. Must be a key in var_file:
                'firewall', 'filepos', 'backup', 'lastutmp',
                'missingsync', or 'blacknets_cache'.

        Returns:
            Path object pointing to the requested file
            (e.g., /var/lib/nftfw/firewall.db).

        Raises:
            AssertionError: If name is not in var_file.

        Example:
            db_path = config.varfilepath('firewall')  # Returns Path to firewall.db
            backup = config.varfilepath('backup')     # Returns Path to nftables.backup

        Note:
            Results are cached for performance.
            The actual filename is determined by var_file mapping.
        """
        p = self.get_ini_value_from_section('Locations', 'sysvar')
        base = Path(cast(str, p))
        assert name in self.var_file, f'{name} not in var_file'
        dir_path = base / self.var_file[name]
        return dir_path

    @cache
    def etcpath(self, name: str) -> Path:
        """Get full path to a directory in nftfw's etc directory.

        Returns the path to configuration directories containing rules,
        patterns, and other user-editable configuration files.

        Args:
            name: Directory identifier. Must be a key in etc_dir:
                'incoming', 'outgoing', 'whitelist', 'blacklist',
                'blacknets', 'patterns', 'rule', or 'local'.

        Returns:
            Path object pointing to the requested directory
            (e.g., /etc/nftfw/incoming.d).

        Raises:
            AssertionError: If name is not in etc_dir.

        Example:
            patterns_dir = config.etcpath('patterns')  # /etc/nftfw/patterns.d
            incoming_dir = config.etcpath('incoming')  # /etc/nftfw/incoming.d

        Note:
            Results are cached for performance.
            The actual directory name is determined by etc_dir mapping.
        """
        base = self.etc_base
        assert name in self.etc_dir, f'{name} not in etc_dir'
        dir_path = base / self.etc_dir[name]
        return dir_path

    #
    # Values as properties
    #
    @property
    def etc_base(self) -> Path:
        """Get the sysetc directory path.

        Returns the base configuration directory path (typically /etc/nftfw)
        where all configuration files and rule directories are stored.

        Returns:
            Path to the sysetc directory.

        Example:
            base_dir = config.etc_base  # Path('/etc/nftfw')
        """
        s = self.get_ini_value_from_section('Locations', 'sysetc')
        base = Path(cast(str, s))
        return base

    @property
    def nftfw_init(self) -> Path:
        """Get the nftfw_init.nft file path.

        Returns the path to the initial nftables configuration file that
        sets up the basic firewall structure.

        Returns:
            Path to nftfw_init.nft file (typically /etc/nftfw/nftfw_init.nft).

        Example:
            init_file = config.nftfw_init
        """
        s = self.get_ini_value_from_section('Locations', 'nftfw_init')
        base = Path(cast(str, s))
        return base

    @property
    def nftables_conf(self) -> Path:
        """Get the system nftables.conf file path.

        Returns the path to the system's nftables configuration file.
        For production systems, this should be /etc/nftables.conf.
        For new installations, it defaults to {sysetc}/nftables.conf
        to avoid breaking existing system configurations.

        Returns:
            Path to nftables.conf file.

        Example:
            nft_conf = config.nftables_conf

        Note:
            Installers are asked to change this to /etc/nftables.conf
            after verifying the nftfw configuration works correctly.
        """
        s = self.get_ini_value_from_section('Locations', 'nftables_conf')
        return Path(cast(str, s))
