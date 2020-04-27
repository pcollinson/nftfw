"""nftfw RulesReader class

Rules are small shell scripts which are accessed from the firewall
directory, they are used to generate nft commands

"""

import subprocess
import logging
from ruleserr import RulesReaderError
log = logging.getLogger('nftfw')

class RulesReader:
    """ RulesReader class

    Parameter: config class

    when initialised reads rules and creates a dict of rule names and
    content

    Also syntax checks all the files on first instanciation

    Provides method to execute the rule using a known enviroment

    Can raise RulesReaderError exception placed in a separate file to
    allow external access without this file having to be imported
    """

    # The rules that are read need to be shared across all versions of
    # this class, they are stored in this static Class variable, and
    # then can be accessed using the property rules
    rules_store = None

    def __init__(self, cf):
        """ Initialise Rules
        Parameters
        ----------
        cf : Config
        """

        self.cf = cf
        self.rulepath = cf.etcpath('rule')
        if RulesReader.rules_store is None:
            files = (f for f in self.rulepath.glob('*.sh') if f.is_file())
            rules = ((p.stem, p.read_text()) for p in files)
            RulesReader.rules_store = {r:c for r, c in rules if any(c)}
            # This may raise an exception
            # so starting this class needs to use a try to report any error
            self.checksyntax()

    @property
    def rules(self):
        """ property to access the rules """
        return RulesReader.rules_store

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
        errorfiles = []
        for key in self.keys():
            try:
                self.execute(key, env)
            except RulesReaderError:
                errorfiles.append(key + '.sh')

        if any(errorfiles):
            errors = ", ".join(errorfiles)
            path = str(self.rulepath)
            raise RulesReaderError(f'Problems with {errors}, check files in {path} with shell')

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
                               env=env)

        if compl.returncode != 0:
            err = f'Action {key}: returned error code'
            raise RulesReaderError(err)
        elif compl.stderr != b'':
            err = f'Action {key}: returned error {compl.stderr.decode()}'
            raise RulesReaderError(err)
        else:
            return compl.stdout.decode()
