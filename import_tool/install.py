"""Install files from the computed rules in a specific location

Used to generate the test directory and final output

"""

import sys
import os
from fwdb import FwDb

class Installer:
    """ Install directories, files and database entries """

    def __init__(self, cf, install_is_silent):
        """ Called with boolean to suppress printing """

        self.cf = cf
        # flag to iprint()
        self.install_is_silent = install_is_silent

    def install_files(self, target, installdirs, rl_objs, uid=None, gid=None):
        """ Initialise install target structure
        if needed - create directories and delete files in the target
        directory and it's children

        target        Path to target directory
        installdirs   array of {name : directory string }
        rl_objs      {'key': ProcessRulesObject|ProcessListsObject,
                      'key': ProcessRulesObject|ProcessListsObject}
        uid          Uid of target files can be unset and then
                     chown is not attempted
        gid          Gid of target files

        Values in Process*Object.records that are used:
        nftfwaction: ignore install if == ignore, unknown, duplicate
        outname:     filename to use
        stat:        Stat of original file, set times on new file
        """

        # pylint: disable=too-many-arguments

        installpaths = self.setup_paths(installdirs, target, uid, gid)
        self.do_installation(installpaths, rl_objs, uid, gid)

    def do_installation(self, installpaths, rl_objs, uid, gid):
        """ Create files in the target

        installpaths:   {'name': Path to directory, ..}
        rl_objs.records  Holds list of records to be processed
        uid,gid         Owner to set, unless uid is None
    """
        usechown = False
        if uid is not None:
            usechown = True

        for name, dirpath in installpaths.items():
            # do we need to install disabled files?
            if hasattr(rl_objs[name], 'is_disabled') \
               and rl_objs[name].is_disabled:
                destpath = dirpath / 'disabled'
                destpath.touch(exist_ok=True)
            # process records
            records = rl_objs[name].records
            work = (r for r in records if not self.cf.skiprecord(r))
            for rec in work:
                destpath = dirpath / rec['outname']
                self.iprint(f'Writing {str(destpath)}')
                destpath.write_text(rec['contents'])
                # set up original access and mtime
                if rec['stat']:
                    os.utime(destpath, (float(rec['stat'].st_atime), float(rec['stat'].st_mtime)))
                if usechown:
                    os.chown(destpath, uid, gid)

    def install_database(self, listobjs):
        """Scan the records from ProcessLists from the
        blacklist call and update the firewall database if needed"""

        # select the entries we need to update
        updateneeded = [rec for rec in listobjs.records \
                        if rec['is_auto'] \
                        and not rec['in_nftfwdb'] \
                        and not self.cf.skiprecord(rec)]
        if updateneeded:
            # Open the database, pass createdb as True if the
            # database file doesn't exist
            create_the_db = not self.cf.nftfw_firewall_path.exists()
            fwdb = FwDb(self.cf, createdb=create_the_db)
            for rec in updateneeded:
                self.iprint(f"Adding {rec['ip']} to database")
                dbrec = self.construct_db_record(rec)
                fwdb.insert_ip(dbrec)
            fwdb.close()

    def safe_mkdir(self, dirpath):
        """ Make a directory and bail out if cannot """

        try:
            dirpath.mkdir(mode=0o775)
        except PermissionError as e:
            self.fatal(f'Cannot create {str(dirpath)} - {str(e)}')

    @staticmethod
    def fatal(printme):
        """ Print string and die """

        print('*** Fatal installation problem')
        print(printme)
        sys.exit(1)

    def setup_paths(self, installdirs, basepath, uid, gid):
        """ Set up paths to install directories and return them

        If the base directory doesn't exist then create it
        If the install directories don't exist then create them
        If the install directories contain anything, then delete it

        Parameters
        ----------
        installdirs:   array of {internal name, directory name}

        basepath:      path to the base of the tree, this is used
                       to create the testing directory structure
                       and also the live control directory should that be needed.

        returns   the directories as dict of {internal name, Path}
        """

        # pylint: disable=too-many-branches

        usechown = False
        if uid is not None:
            usechown = True

        if not basepath.exists():
            self.safe_mkdir(basepath)
            self.iprint(f'Create {str(basepath)}')
            if usechown:
                os.chown(basepath, uid, gid)
        if not basepath.is_dir():
            self.fatal(f'{str(basepath)} exists and is not a directory')
        if not os.access(basepath, os.W_OK):
            self.fatal(f'No write access to {str(basepath)}')

        installpaths = {}
        for name, subd in installdirs.items():
            installpaths[name] = basepath / subd
            if not installpaths[name].exists():
                self.safe_mkdir(installpaths[name])
                if not os.access(installpaths[name], os.W_OK):
                    self.fatal(f'No write access to {str(installpaths[name])}')
                if usechown:
                    os.chown(installpaths[name], uid, gid)
                self.iprint(f'Create {str(installpaths[name])}')
            else:
                if not os.access(installpaths[name], os.W_OK):
                    self.fatal(f'No write access to {str(installpaths[name])}')
                # get directory contents
                contents = (f for f in installpaths[name].iterdir() if f.is_file())
                try:
                    self.iprint(f'Cleaning {str(installpaths[name])}')
                    for rem in contents:
                        rem.unlink()
                except PermissionError as e:
                    self.fatal(f'You don\'t have access to {str(installpaths[name])} - {str(e)}')
        return installpaths

    def construct_db_record(self, rec):
        """ Make a database record from the record """

        outrec = {}
        # ip address
        outrec['ip'] = rec['ip']
        # pattern - not in Sympl/Symbiosis - use 'import'
        outrec['pattern'] = 'import'
        # incident count
        outrec['incidents'] = 1
        # matchcount - set to 10 to ensure the ip is still
        # blacklisted
        outrec['matchcount'] = 10
        # Times
        outrec['first'] = rec['stat'].st_mtime
        outrec['last'] = outrec['first']
        # ports
        outrec['ports'] = self.portcheck(rec['contents'])
        # the 'useall' flag
        outrec['useall'] = False
        if outrec['ports'] == 'all':
            outrec['useall'] = True
        outrec['multiple'] = False
        outrec['isdnsbl'] = False
        return outrec

    @staticmethod
    def portcheck(ptstr):
        """Check and validate port list from string

        Check file contents:

        If list is empty - return 'all'
        If contents contains 'all' return 'all'
        Otherwise it should be a numeric list
        one per line

        Make into a sorted list
        return as comma separated
        ignore any blank lines, and lines
        which don't contain numeric values

        Parameters
        ----------
        ptstr : str
            Ports on several lines with possible white space

        Returns
        -------
        str
            Cleaned and validated comma separated list of ports
        """

        # Look for 'all' in contents
        if 'all' in ptstr.casefold():
            return 'all'
        # make an array of ints so we can sort them
        # shouldn't have commas, but people may type them
        pt = ptstr.replace(',', '\n')
        # split at newlines also lose any whitespace
        li = [n.strip() for n in pt.split("\n") \
              if n.strip().isnumeric()]
        if any(li):
            li = list(set(li))
            li = sorted(li, key=int)
            return ','.join(li)
        return 'all'

    def iprint(self, strtoprint):
        """ Print if is_silent is False """

        if not self.install_is_silent:
            print(strtoprint)
