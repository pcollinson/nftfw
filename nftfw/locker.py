#!/usr/bin/env python
""" nftfw lock management

Class to provide a lock on a file
Called with a filename to use as a lock

Then
lockfile()     Blocks until lock is obtained, returns False
               if cannot open file or lock error
nb_lockfile()  Uses non-blocking and returns False if the lock isn't obtained
               returns True if it's obtained
               Keep the fd in the globals vector so it remains open
unlock()       Unlocks the file
"""

import sys
import fcntl
import logging
log = logging.getLogger('nftfw')

class Locker:
    """Class to provide a lock on a file

    Called with a filename to use as a lock
    """

    def __init__(self, filename):
        """Initialise

        Parameter
        ---------
        filename : str
        """

        self.filename = filename
        self.fd = None

    def lockfile(self):
        """Blocks until lock is obtained,

        returns False if cannot open file or lock error
        """

        # pylint: disable=consider-using-with
        try:
            self.fd = open(self.filename, 'w+')
        except IOError as e:
            log.error('Fatal error: Attempt to lock using %s: %s',
                      self.filename, str(e))
            sys.exit(1)

        try:
            fcntl.flock(self.fd, fcntl.LOCK_EX)
            return True
        except IOError:
            return False

    def nb_lockfile(self):
        """Uses non-blocking and returns False
        if the lock isn't obtained

        returns True if it's obtained
        """

        # pylint: disable=consider-using-with
        try:
            self.fd = open(self.filename, 'w+')
        except IOError as e:
            log.error('Fatal error: Attempt to lock using %s: %s',
                      self.filename, str(e))
            sys.exit(1)
        try:
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except IOError:
            return False

    def unlockfile(self):
        """Unlocks the file """

        if self.fd:
            fcntl.flock(self.fd, fcntl.LOCK_UN)
            self.fd.close()
            self.fd = None
