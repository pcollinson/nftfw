"""nftfw configuration class

Passed into every class used in the system to convey system settings.

Uses ConfigParser to
    read compiled in default ini file settings
    read external ini file settings
    settings can also be changed by program arguments

Establishes logging used in all modules, allows logging setting
changes from config files and command line - managed by loggermanager

Provides API to access the settings
and in some cases properties to return values

"""
import os
import sys
from functools import wraps
from pathlib import Path
from configparser import ConfigParser, ExtendedInterpolation
from configparser import Error as ConfigParserError
import logging
from loggermanager import LoggerManager
log = logging.getLogger('nftfw')

def cache(func):
    """Decorator to cache path lookup values"""

    saved = {}
    @wraps(func)
    def newfunc(*arg):
        if arg[1] in saved.keys():
            return saved[arg[1]]
        result = func(*arg)
        saved[arg[1]] = result
        return result
    return newfunc

class Config:
    """Configuration class

    Establish constants.

    Use config.ini to override variables
    Then setup logging

    dosetup = False allows value changing before calling setup

    Config values       Copied to config attributes
    -------------
    [Locations]
    root : str          prefix used by all directory  definitions.
                        added automatically on startup.
    sysetc : str        Path to etc directory used to store config
                        and other information
    sysvar : str        Path to var/lib/nftfw storing working files
                        and rules
    ini_file : str      where to find the default config.ini file
                        Only in global file, can be changed
                        using -c argument
    nftables_conf : str location of the systems nftables.conf file
                        set in this file to /etc/nftables.conf
                        overridden in the initial config.ini file

    nftables_conf : str Location of system nftables.conf
                        Should be /etc/nftables.conf for production.
                        But because we don't want to kill people's
                        systems when they first install nftfw
                        This will default to {sysexec}/nftables.conf
                        and installers will be asked to change it.

    [Rules]             map default fw settings to commands in rules
                        Possible to use 'drop' for reject here
    incoming = accept
    outgoing = reject
    whitelist = accept
    blacklist = reject
    blacknets = drop

    [Logging]
    logfmt : str        Logger format string for logger use
    loglevel : str      Default log level name as a string
    logfacility : str   Default log facility name as a string
    logprint : bool     If true print logs, cannot be set
                        during program running. Set to false
                        if program is not talking to a terminal
    logsyslog : bool    If true log to syslog

    [Nft]               Nftables settings passed into the rules scripts:
    incoming_counter :  bool  Add counter to incoming rules
    outgoing_counter :  bool
    blacklist_counter : bool
    whitelist_counter : bool
    blacknets_counter : bool

    incoming_logging  :  str  String to add to logging for incoming rules
    outgoing_logging  : str
    blacklist_logging : str
    whitelist_logging : str
    blacknets_logging : str

                          The three variables below control the type
                          of sets automatically generated for
                          blacklist, blacknets and whitelist tables.
                          When true, nftfw uses auto_merged, interval
                          sets for the sets it makes. This set type
                          automatically create single entries
                          containing an address range for adjacent IP
                          addresses. The feature is desirable because
                          it reduces the number of matches.

                          However, at present, the auto-merged,
                          interval sets can cause the nft program to
                          fail, flagging an error. There is a bug
                          causing nft to succeed in loading the set
                          when a full install is performed but failing
                          when attempting a reload.

                          The bug has been reported to the nftables
                          development team, but no fix has been
                          generated as of the current releases. nftfw
                          will work around this bug, automatically
                          generating a full install when an attempt at
                          a set reload fails. However, it seems a good
                          idea to provide a way of turning this
                          feature on and default to not using the feature.

    blacklist_set_auto_merge : bool
    whitelist_set_auto_merge : bool
    blacknets_set_auto_merge : bool

    [Whitelist]
    wtmp_file : str        Wtmp file to scan, empty to use the system
                           default. Set wtmp_file=utmp to use the system
                           default utmp file, otherwise set to a file

    whitelist_expiry : int Days after which automatically generated
                           whitelist entries are expired from the system

    [Blacklist]
    Constants to manage blacklisting these depend on the matchcount value
    found from the logreader script NB Symbiosis had multiple records for
    each ip. This system only has one record but records timestamps. Expiry
    uses the complete record of activity from the ip

    block_after: int 10     Value in matchcount after which
                            an ip is blocked using the ports in
                            the rule (Symbiosis used 2)
    block_all_after:int 100 Value in matchcount after which
                            an ip is blocked using all ports

    These depend on the time of last incident
    expire_after:int 10     Number of days after which blacklisted ips
                            should be expired. Symbiosis used 2

    clean_before:int 90     Database clean
                            remove ip from the database where there has been
                            no error posted for more than these number of days

    sync_check:int 50       'nftfw blacklist' will check whether the IP addresses
                            in the database that should be active are actually present
                            in the blacklist directory _blacklist.d_. 'Should be active'
                            means that the addresses have not been automatically expired.
                            'nftfw' is largely event driven, but events get missed. So
                            on the basis that if stuff can happen, it will, this code
                            will recover the correct state of the blacklist directory.
                            It seems overkill to call this every time the blacklist scanner
                            runs, so it is executed when number of runs of the scanner
                            is greater than the value of this variable. The default is
                            to run the blacklist scanner 96 times a day, so 50 seems
                            are reasonable way to run the recovery code once a day. Set
                            this to zero  to turn this feature off.

    [Nftfwls]
    Allow local selection for date formats in nftfwls
    Seconds are not that relevant
    default: dd-mm-YYYY HH:MM
    date_fmt: str  %d-%m-%Y %H:%M

    pattern_split: bool     If true replaces ',' in pattern column
                            by a newline and a space, to reduce output
                            width

    [Nftfwedit]
    Supply strings to lookup DNSBL sites. Format is
    Name=domain name for lookup
    only handles IPv4 addresses


    """

    # pylint: disable=too-many-instance-attributes, too-many-lines
    # This is a config class and needs loads

    # Default settings
    # These values are all imported into
    # this class
    default_parser_settings = """
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
# The bug has been reported to the nftables development team, but no
# fix has been generated as of the current releases. nftfw will work
# around this bug, automatically generating a full install when an
# attempt at a set reload fails. However, it seems a good idea to
# provide a way of turning this feature on and default to not using
# the feature.
#
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
    rootlist = ('', '/usr/local')

    # Directories we expect to find in sysetc
    etc_dir = {'incoming':  'incoming.d',
                'outgoing':  'outgoing.d',
                'whitelist': 'whitelist.d',
                'blacklist': 'blacklist.d',
                'blacknets': 'blacknets.d',
                'patterns':  'patterns.d',
                'rule':      'rule.d',
                'local':     'local.d'}

    # Directories we expect to find in the sysvar
    var_dir = {'build': 'build.d',
               'install': 'install.d',
               'test': 'test.d'}

    # Files we expect to find in the sysvar
    var_file = {'firewall' : 'firewall.db',
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
    create_build_only = False
    #
    #   if true force a full install of firewall
    #   (-f flag)
    force_full_install = False

    #
    #   pattern name selected by the -p option
    #
    selected_pattern_file = None
    #
    #   flag to say that the single pattern file
    #   is a test file, set when the pattern file is read
    selected_pattern_is_test = False

    #   Some modules poke values into here to allow global access.
    #   These are documented here
    #
    #   Used by firewallreader.py
    rulesreader = None

    #   Used by nftfwedit.py to pass args through the scheduler
    editargs = {}

    #   Ini file support
    #   These are attributes we expect to find in the ini file
    #   Used to check on names for the -o option
    #   and also for deciding on type of ini variables
    ini_string_change = (
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
        'expire_after', 'clean_before', 'date_fmt')

    ini_boolean_change = (
        'logprint', 'logsyslog',
        'incoming_counter', 'outgoing_counter',
        'blacklist_counter', 'whitelist_counter',
        'blacknets_counter',
        'blacklist_set_auto_merge',
        'whitelist_set_auto_merge',
        'blacknets_set_auto_merge',
        'pattern_split')

    def __init__(self, dosetup=True, localroot=None):
        """Set up constants and logging

        Use config.ini to override variables
        Then setup logging

        Ini file and logger processing split into three functions:
        __init__  loads default settings
        readini() reads the ini file configurable by user
        setup()   establishes final settings

        The main scripts provide extra processing between
        these steps. Callers need to trap AssertionError
        to bail out cleanly.

        Parameters
        ----------
        dosetup : bool
                  If false, expects the caller to directly
                  call readini() and setup()
        localroot: string
                  The code that looks for root needs disabling
                  when running tests.
                  This argument will set the root and skip
                  establish root tests
        """

        # establish parser and load default values
        self.parser = ConfigParser(allow_no_value=True,
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
        self.inireverse = {}

        # Setup code doesn't need to use the logging system
        # but this allows that if needed
        logvars = self.get_ini_values_by_section('Logging')
        # installing this could be a simple loop but let's stop pylint complaining
        self.logfmt = logvars['logfmt']
        self.loglevel = logvars['loglevel']
        self.logfacility = logvars['logfacility']
        self.logprint = logvars['logprint']
        self.logsyslog = logvars['logsyslog']

        # these are used in chownpath
        # see chownpath
        # default to root:root
        self.fileuid = 0
        self.filegid = 0

        # now setup loggermanager
        self.logger_mgr = LoggerManager(self, log)

        # if dosetup is false then
        # the caller has to do these
        if dosetup:
            self.readini()
            self.setup()

    def _establishroot(self):
        """Look on system to find the root for the nftfw files

        Sets 'root' in the ini file to establish paths to other
        ini location variables
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

    def readini(self):
        """Read the defined ini file if any

        Turns off logging if the stdout is not a tty
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

        assert not errors, 'config.ini syntax errors: {0}'.format(' '.join(errors))

        # turn off printing by default unless talking to a terminal
        # but can be overridden from config files and arguments
        if not sys.stdout.isatty():
            self.set_ini_value_with_section('Logging', 'logprint', False)

    def setup(self):
        """Establish final settings

        There may have been some variable changes
        Calls logger manager to set these
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

        # Finally check on the installation
        self._check_installation()

    def _check_installation(self):
        """ Check control directories

        Check that all the needed control directories
        exist. Raise assert exception if not there.
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
        sysvar = Path(p)
        if not sysvar.is_dir():
            missing.append(str(sysvar))
        else:
            for name in self.var_dir:
                dir_path = sysvar / self.var_dir[name]
                if not dir_path.is_dir():
                    missing.append(str(dir_path))

        # log list is not empty
        assert not missing, 'Missing configuration directories/files: {0}'.format(" ".join(missing))

    def set_logger(self, logprint=None,
                   logsyslog=None, loglevel=None):
        """Set logger values from various main functions

        Support for the -q and -v flag
        Copies values into ConfigFile data
        Sets loggermanager appropriately

        Parameters
        ----------
        logprint : bool
            Turn logging to console on or off
        logsyslog : bool
            Turn logging to syslog on or off
        loglevel : str
            Provide loglevel

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
    def set_ini_value_with_section(self, section, option, value):
        """Load parser ini values using named section

        Parameters
        ----------
        section : str
            Section name to use
        option : str
            Option to set
        value : str / bool
            If option flagged as a boolean will change from
            True/False into string version used by ConfigParser
        """

        if option in self.ini_boolean_change:
            value = 'True' if value else 'False'
        self.parser.set(section, option, value)

    def set_ini_value(self, option, value):
        """Set an ini value with an unknown section

        Creates a reverse index of option names to sections

        Parameters
        ---------
        option : str
        Option to set
        value : str / bool
        If option flagged as a boolean will change from
        True/False into string version used by ConfigParser
        """

        if not any(self.inireverse):
            self._make_inireverse()
        if option in self.inireverse.keys():
            self.set_ini_value_with_section(self.inireverse[option], option, value)
        else:
            log.error('Cannot find option %s to set', option)

    def get_ini_value_from_section(self, section, option):
        """Get an initialisation value from section

        Parameters
        ----------
        section : str
            Section name to use
        option : str
            Option to get

        Returns
        -------
        str | bool
            String value, or bool if option is bool
            Caller needs to change int values
        """

        value = self.parser.get(section, option)
        if option in self.ini_boolean_change:
            value = (value == 'True')
        return value

    def get_ini_values_by_section(self, section):
        """Return a dict of all values in a section

        Parameters
        ----------
        section : str
            Section name to use

        Returns
        -------
        dict
            key is option name
            value : str | bool
        """

        out = {}
        for k, v in self.parser[section].items():
            if k in self.ini_boolean_change:
                v = (v == 'True')
            out[k] = v
        return out

    def _make_inireverse(self):
        """Make a dictionary mapping keys into sections

        Sets self.inireverse to reverse mapping dict
        """

        out = {}
        sects = self.parser.sections()
        for s in sects:
            for o in self.parser[s]:
                out[o] = s
        self.inireverse = out

    def get_ini_changed_values(self):
        """ Compare working ini setting with default

        Returns
        -------
        String that can be printed
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
    def am_i_root():
        """Check if running as root and die if not"""

        if os.geteuid() != 0:
            print("Run the program as root")
            sys.exit(1)

    def chownpath(self, path):
        """Given a path, set its owner

        unless the default uid,gid = root,root

        Parameters
        ----------
        path : str
            File to change
        """
        if self.fileuid == 0 \
           and self.filegid == 0:
            return
        os.chown(path, self.fileuid, self.filegid)

    def config_settings(self, parser):
        """Return config settings as str"""

        out = []
        sects = parser.sections()
        for s in sects:
            out.append('['+s+']')
            for o in parser[s]:
                if o in self.ini_boolean_change:
                    v = parser.getboolean(s, o)
                    out.append(f'{o} = {str(v)}')
                else:
                    v = parser.get(s, o, raw=True)
                    if v is None:
                        out.append(o)
                    else:
                        out.append(f'{o} = {v}')
        return "\n".join(out)

    def __repr__(self):
        """Return config settings as str"""

        return self.config_settings(self.parser)

    #
    # Directory and file location API
    #
    @cache
    def varpath(self, name):
        """Create a full path to a dir in nftfw's var dir

        The function also switches build destination when
        testing.

        Parameters
        ----------
        name : str
            String name of directory
            Must be in self.var_dir

        Returns
        -------
        Path
            Path to directory in the working directory
        """

        p = self.get_ini_value_from_section('Locations', 'sysvar')
        base = Path(p)
        # switch to test if testing
        if name == 'build' \
           and self.create_build_only:
            name = 'test'
        assert name in self.var_dir, f'{name} not in var_dir'
        dir_path = base / self.var_dir[name]
        return dir_path

    @cache
    def varfilepath(self, name):
        """Create a full path to a dir in nftfw's var dir

        Parameters
        ----------
        name : str
            String name of directory
            Must be in self.var_file

        Returns
        -------
        Path
            Path to file in the working directory
        """

        p = self.get_ini_value_from_section('Locations', 'sysvar')
        base = Path(p)
        assert name in self.var_file, f'{name} not in var_file'
        dir_path = base / self.var_file[name]
        return dir_path

    @cache
    def etcpath(self, name):
        """Create a full path to a dir in nftfw's etc dir

        Finding path to

        Parameters
        ----------
        name : str
            String name of directory
            Must be in self.etc_dir

        Returns
        -------
        Path
            Path to directory in the etc directory
        """

        base = self.etc_base
        assert name in self.etc_dir, f'{name} not in etc_dir'
        dir_path = base / self.etc_dir[name]
        return dir_path

    #
    # Values as properties
    #
    @property
    def etc_base(self):
        """Returns sysetc address as a Path"""

        s = self.get_ini_value_from_section('Locations', 'sysetc')
        base = Path(s)
        return base

    @property
    def nftfw_init(self):
        """Returns nftfw_init address as a Path"""

        s = self.get_ini_value_from_section('Locations', 'nftfw_init')
        base = Path(s)
        return base

    @property
    def nftables_conf(self):
        """Returns nftables.conf"""

        s = self.get_ini_value_from_section('Locations', 'nftables_conf')
        return Path(s)
