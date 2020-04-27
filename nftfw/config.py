"""nftfw configuration class

Passed into every class used in the system to convey system settings.

Uses ConfigParser to
    read compiled in default ini file settings
    read external ini file settings
    settings can also be changed by program
    arguments

Establishes logging used in all modules, allows logging setting
changes from config files and command line - managed by loggermanager

Provides API to access the settings
and in some cases properties to return values

"""
import os
import sys
from functools import wraps
from pathlib import Path
from pwd import getpwnam
from grp import getgrnam
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
    ini_file : str      where to find the default config.py file
                        Only in global file, can be changed
                        using -c argument
    nftables_conf : str location of the systems nfttables.conf file
    nftfw_base : str    Location of the symbiosis style firewall
                        settings. Can be set to /etc/symbiosis.

    [Owner]             Owner used to set ownership of
                        files created in children of etc/nftfw
                        Set to root.root in the default setup
                        Files in var/lib always owned by root
    owner : str
    group : str         Only needed if differs from group of owner

    [Rules]             map default fw settings to commands in rules
                        Possible to use 'drop' for reject here
    incoming = accept
    outgoing = reject
    whitelist = accept
    blacklist = reject

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

    incoming_logging  :  str  String to add to logging for incoming rules
    outgoing_logging  : str
    blacklist_logging : str
    whitelist_logging : str

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

    [Incron]
    using_incron :bool Yes  Set to no if not using incron on the system
                            remember that hand changes to the control
                            files will need you to run nftfw load
                            by hand to set up the firewall
    """

    # pylint: disable=too-many-instance-attributes
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
# system locations used by nftfw
sysetc = ${root}/etc/nftfw
sysvar = ${root}/var/lib/nftfw

#  Default ini file - not tailorable
#  chickens and eggs are the usual explanation
ini_file = ${sysetc}/config.ini

#  Location of system nftables.conf
#  Usually /etc/nftables.conf
nftables_conf = ${root}/etc/nftables.conf

#  Where the initial nft setup for the firewall is found
nftfw_init = ${sysetc}/nftfw_init.nft

#
#  This is where to look for the various directories
#  that manage the system.
#  On a system with symbiosis installed can be set to
#  /etc/symbiosis
#  NB Symbiosis files in local.d are not supported
#  by this system. To provide local changes, edit
#  etc/nftfw_init.nft
nftfw_base = ${sysetc}

[Owner]
# Owner used to set ownership of files created
# in children of etc/nftfw
# Set to root.root in the default setup -
# Files in var/lib always owned by root
owner = root
# group only needed if differs from that
# of owner
group

[Rules]
#   Default rules for incoming and outgoing
#   Possible to use 'drop' for reject here
incoming = accept
outgoing = reject
whitelist = accept
blacklist = reject

[Logging]
#  System Logging constants
#
#  Format of log statements
logfmt = nftfw[%(process)d]: %(message)s
#  what level are we logging at
#  needs to be a level name not a value
#  CRITICAL, ERROR, WARNING, INFO, DEBUG
#  Use ERROR for production
loglevel = ERROR
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
#  do we want nftables logging?
#  this adds a different prefix for each of the tables
#  when logged
#  use empty value to mean none
incoming_logging
outgoing_logging
blacklist_logging = Blacklist
whitelist_logging

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

[Incron]
# Set to no if not using incron on the system
# remember that hand changes to the control
# files will need you to run nftfw load
# by hand to set up the firewall
using_incron = Yes

"""

    # Where to look for root files
    # list of prefixes
    # '' is basically /
    rootlist = ('', '/usr/local')

    # Directories we expect to find in the
    # nftfw_base directory which can be different from sysexec
    # where most things live
    nftfw_dir = {'incoming':  'incoming.d',
                 'outgoing':  'outgoing.d',
                 'whitelist': 'whitelist.d',
                 'blacklist': 'blacklist.d',
                 'patterns':  'patterns.d'}

    # Directories we expect to find in the etc/nftfw directory
    etc_dir = {'rule': 'rule.d'}

    # Directories we expect to find in the sysvar
    var_dir = {'build': 'build.d',
               'install': 'install.d',
               'test': 'test.d'}

    # Files we expect to find in the sysvar
    var_file = {'firewall' : 'firewall.db',
                'filepos'  : 'filepos.db',
                'backup'   : 'nftables.backup',
                'lastutmp' : 'whitelist_scan'}

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
        'sysetc', 'sysvar',
        'nftables_conf', 'nftfw_init', 'nftfw_base',
        'owner', 'group',
        'wtmp_file', 'whitelist_scan',
        'incoming', 'outgoing', 'whitelist', 'blacklist',
        'logfmt', 'loglevel',
        'logfacility', 'incoming_logging',
        'outgoing_logging', 'blacklist_logging',
        'whitelist_logging', 'whitelist_expiry',
        'block_after', 'block_all_after',
        'expire_after', 'clean_before', 'date_fmt')

    ini_boolean_change = (
        'logprint', 'logsyslog',
        'incoming_counter', 'outgoing_counter',
        'blacklist_counter', 'whitelist_counter',
        'pattern_split', 'using_incron')


    def __init__(self, dosetup=True):
        """Set up constants and logging

        Use config.ini to override variables
        Then setup logging

        Ini file and logger processing split into three functions:
        __init__  loads default settings
        readini() reads the ini file configurable by user
        setup()   establishes final settings

        The main scripts provide extra processing between
        these steps.

        Parameters
        ----------
        dosetup : bool
                  If false, expects the caller to directly
                  call readini() and setup()
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
        self._establishroot()

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

        # these are set in chownpath
        # see chownpath
        self.owner = None
        self.group = None
        self.fileuid = None
        self.filegid = None

        # cache and flag for preset for using_incron property
        self._using_incron = None

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
                if Path(sysetc).exists():
                    return
        self.parser.set('Locations', 'root', '')

    def readini(self):
        """Read the defined ini file if any

        Turns off logging if the stdout is not a tty
        """

        errors = []
        try:
            ini_file = self.parser.get('Locations', 'ini_file')
            if not os.path.isfile(ini_file):
                return
            self.parser.read(ini_file)
        except ConfigParserError as e:
            errors.append(str(e))
        if any(errors):
            for line in errors:
                print(line)
                sys.exit(1)

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
        if self.fileuid is None:
            if self.owner is None:
                # Same for owner and group
                logvars = self.get_ini_values_by_section('Owner')
                self.owner = logvars['owner']
                self.group = logvars['group']
            # set up ownership of files that are created
            pw = getpwnam(self.owner)
            self.fileuid = pw.pw_uid
            self.filegid = pw.pw_gid
            if self.group is not None \
               and self.group != '':
                gp = getgrnam(self.group)
                self.filegid = gp.gr_gid

        if self.fileuid == 0 \
           and self.filegid == 0:
            return
        os.chown(path, self.fileuid, self.filegid)

    def __repr__(self):
        """Return config settings as str"""

        out = []
        sects = self.parser.sections()
        for s in sects:
            out.append('['+s+']')
            for o in self.parser[s]:
                if o in self.ini_boolean_change:
                    v = self.parser.getboolean(s, o)
                    out.append(f'{o} = {str(v)}')
                else:
                    v = self.parser.get(s, o, raw=True)
                    if v is None:
                        out.append(o)
                    else:
                        out.append(f'{o} = {v}')
        return "\n".join(out)

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
    def nftfwpath(self, name):
        """Create a full path to a dir in nftfw's nftfw_dir dir

        Finding path to control directories

        Parameters
        ----------
        name : str
            String name of directory
            Must be in self.nftfw_dir

        Returns
        -------
        Path
            Path to directory in the control directory
        """

        s = self.get_ini_value_from_section('Locations', 'nftfw_base')
        base = Path(s)
        assert name in self.nftfw_dir, f'{name} not in nftfw_dir'
        dir_path = base / self.nftfw_dir[name]
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

        s = self.get_ini_value_from_section('Locations', 'sysetc')
        base = Path(s)
        assert name in self.etc_dir, f'{name} not in etc_dir'
        dir_path = base / self.etc_dir[name]
        return dir_path

    #
    # Values as properties
    #
    @property
    def nftfw_base(self):
        """Returns nftfw_base address as a Path"""

        s = self.get_ini_value_from_section('Locations', 'nftfw_base')
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

    @property
    def using_incron(self):
        """Returns a boolean"""

        if self._using_incron is None:
            self._using_incron = self.get_ini_value_from_section('Incron', 'using_incron')
        return self._using_incron
