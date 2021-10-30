"""nftfw RulesReader class

Rules are small shell scripts which are accessed from the firewall
directory, they are used to generate nft commands. They live in rule.d
with local variations installed in local.d

"""

import os
import subprocess
import logging
from .ruleserr import RulesReaderError
log = logging.getLogger('nftfw')

class RulesReader:
    """ RulesReader class

    Parameter: config class

    when initialised reads rules and creates a dict of rule names and
    content

    Also syntax checks all the files on first instantiation

    Provides method to execute the rule using a known enviroment

    Can raise RulesReaderError exception placed in a separate file to
    allow external access without this file having to be imported
    """

    # The rules that are read need to be shared across all versions of
    # this class, they are stored in this static Class variable, and
    # then can be accessed using the property rules
    rules_store = None
    # maps keys to files
    rules_dir = None

    def __init__(self, cf):
        """ Initialise Rules
        Parameters
        ----------
        cf : Config
        """

        self.cf = cf
        if RulesReader.rules_store is None:
            localpath = cf.etcpath('local')
            rulepath = cf.etcpath('rule')
            # get file names
            localfiles = {p.stem:p \
                          for p in localpath.glob('*.sh') if p.is_file()} \
                              if localpath.exists() else {}
            rulefiles = {p.stem:p \
                         for p in rulepath.glob('*.sh') if p.is_file()} \
                             if rulepath.exists() else {}
            # merge: localfiles entries replace any rulefiles
            rulesdir = {**rulefiles, **localfiles}
            # read contents
            rules = ((stem, rulesdir[stem].read_text()) \
                     for stem in rulesdir)
            # create dictionary
            RulesReader.rules_store = {r:c for r, c in rules if any(c)}
            # and access to rulesdir - for testing purposes
            RulesReader.rules_dir = rulesdir
            # This may raise an exception
            # so starting this class needs to use a try to report any error
            self.checksyntax()

    @property
    def rules(self):
        """ property to access the rules """
        return RulesReader.rules_store

    @property
    def rulesdir(self):
        """ property to access the rulesdir """
        return RulesReader.rules_dir

    def items(self):
        """ Return iterable items """
        for k, v in self.rules.items():
            yield (k, v)

    def exists(self, key):
        """ Check if a rule exists """
        return key in self.rules

    def contents(self, key):
        """ Return contents of a rule """
        return self.rules[key]

    def keys(self):
        """ Return key list """
        for k in self.rules.keys():
            yield k

    def checksyntax(self):
        """ Run all commands through shell
        Abandon and raise error if this fails
        Run on first instanciation of the class
        """

        env = {}
        errorkeys = []
        for key in self.keys():
            try:
                self.execute(key, env)
            except RulesReaderError:
                errorkeys.append(key)

        if any(errorkeys):
            errorfiles = []
            for key in errorkeys:
                errpath = self.rulesdir[key]
                filename = errpath.name
                parentname = errpath.parent.name
                shortname = f'{parentname}/{filename}'
                errorfiles.append(shortname)
            errors = ", ".join(errorfiles)
            errstr = f'Syntax problems with {errors}. Run /bin/sh on files to check for errors.'
            raise RulesReaderError(errstr)

    def demote(self):
        """ Demote owner of shell scripts

            In 3.9, subprocess.run has user and group arguments
            but they are not there in 3.7, so this technique has
            to be used
        """

        if os.getuid() == 0:
            os.setgid(self.cf.execgid)
            os.setuid(self.cf.execuid)

    def execute(self, key, env):
        """ Execute a rule

        Parameters
        ----------
        key : str
        env : Dict

        Returns
        -------
        str - result of shell script

        raises exceptions on errors

        key should be checked for validity before calling execute

        Demote running to a mortal user - if that user is available

        This is codes much more easily in 3.7, but has been coded
        with 3.6 API to support subprocess
        """

        if key not in self.rules.keys():
            err = 'Attempted to use unknown rule {key}'
            raise RulesReaderError(err)

        compl = subprocess.run('/bin/sh',
                               input=bytes(self.contents(key), 'utf-8'),
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE,
                               env=env,
                               check=False,
                               preexec_fn = self.demote,
                               # user=self.cf.execuid,
                               # group=self.cf.execgid,
                               start_new_session=True)

        if compl.returncode != 0:
            err = f'Action {key}: returned error code'
            raise RulesReaderError(err)
        if compl.stderr != b'':
            err = f'Action {key}: returned error {compl.stderr.decode()}'
            raise RulesReaderError(err)
        return compl.stdout.decode()
