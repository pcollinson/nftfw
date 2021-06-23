"""Config class for import_firewall

"""

import os
import sys
import re
from pathlib import Path
from configerr import ConfigError

class Config:
    """Class containing configuration constants

    Raises ConfigError when problems occur
"""
    # System type - default
    # easier to look for 'Sympl' and change this if needed
    system_type = 'Symbiosis'

    # Search paths
    # where to look for files
    search = {'nftfw': ('/etc', '/usr/local/etc'),
              'src':   ('/etc/sympl', '/etc/symbiosis'),
              'vars':  ('/var/lib', '/usr/local/var/lib'),
              'rule':  ('/usr/share/sympl/firewall',
                        '/usr/share/symbiosis/firewall')
              }
    debug = False
    # Debug setting look in current directory for nftfw
    # should exist
    # etc/nftfw
    # var/nftfw
    if debug:
        search = {'nftfw': ('etc',),
                  'src':   ('/etc/sympl', '/etc/symbiosis'),
                  'vars':  ('var',),
                  'rule':  ('/usr/share/sympl/firewall',
                            '/usr/share/symbiosis/firewall')
                  }
    # etc Paths
    # out to nftfw, in from src
    etcs = {'nftfw': None, 'src': None}

    # var Paths
    # only want nftfw to get to database
    vars = {'nftfw': None}

    # paths to directories
    paths = {'nftfw': {'rule': None, 'local': None,
                       'incoming': None, 'outgoing': None,
                       'blacklist': None, 'whitelist': None},
             'src': {'rule': None, 'local': None,
                     'incoming': None, 'outgoing': None,
                     'blacklist': None, 'whitelist': None},
             }

    # What to install
    outdirs = {'rules': {'incoming': 'incoming.d', 'outgoing': 'outgoing.d'},
               'lists': {'blacklist': 'blacklist.d', 'whitelist': 'whitelist.d'}
              }

    # Test install destination
    test_install = "/tmp/import_to_nftfw"
    # Final install dir is self.etcs['nftfw']

    # rule names
    # Dictionary of rule names
    # key is name
    # value is name or unwrapped destination of symlinks
    rules = {'nftfw': {'rule': {}, 'local': {}},
             'src': {'rule': {}, 'local': {}}
            }

    # Symbiosis/sympl rules that are not needed
    rules_to_ignore = (
        'new', 'related', 'established',
        'syn-ack-flood-protection', 'essential-icmpv6'
        )
    # Rules to rename
    # and what to rename them to
    rules_to_rename = {'ftp' : ('ftp', 'ftp-passive', 'ftp-helper')}

    # nftfw firewall.db path -
    nftfw_firewall_path = None

    # Owner of target files
    etc_uid = None
    etc_gid = None

    def __init__(self):
        """Find base directories, make paths,
        get rule names

        Raise exception if not found
        """

        # Basic etc directories
        self.etcs['nftfw'] = self.find_dir('nftfw', self.search['nftfw'],
                                           'Cannot find nftfw etc directory')
        self.etcs['src'] = self.find_dir('firewall', self.search['src'],
                                         'Cannot find Sympl or Symbiosis firewall directory')
        self.vars['nftfw'] = self.find_dir('nftfw', self.search['vars'],
                                           'Cannot find nftfw lib/nftfw directory')

        # set system_type looking at the result
        # from find_dir
        if str(self.etcs['src'])[5:10] == 'sympl':
            self.system_type = 'Sympl'

        # get owner of etc/nftfw for installation later
        dirstat = self.etcs['nftfw'].stat()
        self.etc_uid = dirstat.st_uid
        self.etc_gid = dirstat.st_gid

        # look for rules
        self.paths['nftfw']['rule'] = self.etcs['nftfw'] / 'rule.d'
        if not self.paths['nftfw']['rule'].is_dir():
            raise ConfigError('Cannot find nftfw rule.d directory')
        self.paths['src']['rule'] = self.find_dir('rule.d', self.search['rule'],
            f'Cannot find {self.system_type} rule.d directory')

        # look for local directories
        # can be absent
        for outin in ['nftfw', 'src']:
            ruledir = self.etcs[outin] / 'local.d'
            if ruledir.is_dir():
                self.paths[outin]['local'] = ruledir

        # Paths to remaining directories
        for outin in ['nftfw', 'src']:
            for key in self.paths[outin]:
                if key == 'local':
                    continue
                if self.paths[outin][key]:
                    continue
                dirname = key + '.d'
                self.paths[outin][key] = self.etcs[outin] / dirname
                if not self.paths[outin][key].is_dir():
                    raise ConfigError(f'Cannot find directory: {str(self.paths[outin][key])}')

        # Path to lib/nftfw/firewall.db - so needs an exists() check
        fw = self.vars['nftfw'] / 'firewall.db'
        self.nftfw_firewall_path = fw

        # File name matches
        # tuple[0] - glob match
        # tuple[1] - strict regex match
        rulematches = {'nftfw': ('*.sh', r'^.*\.sh$'),
                       'src'  : ('*ing', r'^.*\.(incoming|outging)$')
                      }
        # read rules
        for outin in ('nftfw', 'src'):
            glob, strict = rulematches[outin]

            rulepath = self.paths[outin]['rule']
            self.rules[outin]['rule'] = self.read_rules(rulepath, glob, strict)

            # must have rule.d
            if not self.rules[outin]['rule']:
                errmsg = f'Cannot find rule files in {str(rulepath)}'
                raise ConfigError(errmsg)

            # local.d is optional and may be None
            localpath = self.paths[outin]['local']
            if localpath:
                self.rules[outin]['local'] = self.read_rules(localpath, glob, strict)


    def read_rules(self, dirpath, glob, strictmatch):
        """Get list of rule names from directory
        coping with symlinks

        Parameters
        ----------
        dirpath : Path
            Directory path
        glob: str
            string to match files
        strictmatch: str
            regex to ensure we are looking the right files

        Returns
        -------
        Dict
            Dictionary of names

        """

        names = {}
        links = {}
        strict = re.compile(strictmatch, re.I)
        for file in dirpath.glob(glob):
            if strict.match(file.stem) is not None:
                continue
            if file.is_symlink():
                dest = self.follow_symlink(dirpath, file)
                links[file.stem] = dest.stem
            else:
                names[file.stem] = file.stem

        for name, link in links.items():
            if name not in names \
               and link in names:
                names[name] = link
        return names

    @staticmethod
    def follow_symlink(dirpath, linkfile):
        """Follow symlink to possible destination - being careful of loops """

        while linkfile.is_symlink():
            # only works in 3.9
            #target = linkfile.readlink()
            target = Path(os.readlink(linkfile))
            if str(target)[0] != '/':
                target = dirpath / target
                try:
                    target = target.resolve()
                except RuntimeError as e:
                    raise ConfigError('Symlink loop: ' + str(e))
            linkfile = target
        return linkfile

    @staticmethod
    def find_dir(stem, possibles, errstr):
        """Find a directory in a set of possible locations

        Parameters
        ----------
        stem : str
            String name of directory
        possibles : tuple of str
            List of places to look
        errstr : used as an error in the raise statement
        Returns
        -------
        Path
            Path to directory in the working directory
            None if not found
        """

        for p in possibles:
            base = Path(p)
            lookfor = base / stem
            if lookfor.exists() \
               and lookfor.is_dir():
                return lookfor

        raise ConfigError(errstr)


    def varfilepath(self, name):
        """ To enable the use of the nftfw database code in fwdb:
        provide a Path to /var/lib/nftfw/firewall.db

        name should only be firewall
        """
        if name == 'firewall':
            return self.nftfw_firewall_path
        assert name != 'firewall' 'Call to varfilepath with bad argument {name}'
        return None


    # Shared code

    @staticmethod
    def am_i_root():
        """ Return True if running as root"""

        return os.geteuid() == 0

    @staticmethod
    def skiprecord(rec):
        """ Return true when record processing if
        the record should be skipped
        """
        return rec['nftfwaction'] in ('ignore', 'unknown', 'duplicate')

if __name__ == '__main__':
    # pylint: disable=invalid-name
    from pprint import pprint
    try:
        cf = Config()
    except ConfigError as e:
        print(str(e))
        sys.exit(1)

    print('Nftfw rules')
    pprint(cf.rules['nftfw']['rule'])
    print('Symbiosis/Sympl rules')
    pprint(cf.rules['src']['rule'])
    if cf.rules['nftfw']['local']:
        print('Nftfw locals')
        pprint(cf.rules['nftfw']['local'])
    if cf.rules['src']['local']:
        print('Src locals')
        pprint(cf.rules['src']['local'])
