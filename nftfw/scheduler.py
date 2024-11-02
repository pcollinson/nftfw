""" nftfw work scheduler

Use a lockfile to ensure only one instance is running at any one time.

For commands called automatically from cron, systemd or incron, use a
non-blocking lock, when access to the lock fails, the command is
placed in a queue. Only allow one command of each type in the queue.

'System' commands run and then process the queue before releasing the
lock.

For the other commands - 'user' commands, wait until the lock is
available before running.
"""

from pathlib import Path
from .locker import Locker
from .fwmanage import fw_manage
from .blacklist import BlackList

#pylint: disable=import-outside-toplevel

class Scheduler:
    """ Scheduler Class """

    # imports are dynamic
    # but pylint will complain on bullseye with import-outside-toplevel
    # if the disable code is installed, pylint will complain on buster
    # about the disable code below (now deactivated)
    # pylint argument disable=import-outside-toplevel

    # list of 'user' tasks
    # edit is nftfwedit
    wait = ['clean', 'flush', 'save', 'restore', 'edit']

    # cannot have more than one command
    # user commands all wait to get lock

    def __init__(self, cf):
        """ Set up files """

        self.cf = cf
        sysvar = Path(cf.get_ini_value_from_section('Locations', 'sysvar'))
        self.lockfile = sysvar / 'sched.lock'
        self.queuefile = sysvar / 'sched.queue'
        self.qlockfile = sysvar / 'queue.lock'

    def run(self, command):
        """ Run a command """

        lock = Locker(str(self.lockfile))

        # wait for lock for user commands
        # don't process the queue for background commands
        # treat build_only option to 'load' and 'blacklist'
        #   and if there a single pattern file as 'user' commands

        if command in self.wait \
           or self.cf.create_build_only \
           or self.cf.selected_pattern_file is not None:
            if lock.lockfile():
                self.execute(command)
                # not running the queue for
                # user commands
                # things will catch up
                # on next timed action

        elif not lock.nb_lockfile():
            self.enqueue(command)

        else:
            # we have a lock
            self.execute(command)
            self.processq()

        lock.unlockfile()

    def enqueue(self, command):
        """ Write a command into the queue

        Use hard lock to ensure sole access to queue file

        queuefile contains comma separated list of commands
        """

        lock = Locker(str(self.qlockfile))
        if lock.lockfile():
            q = []
            if self.queuefile.exists():
                line = self.queuefile.read_text()
                q = line.split(',')
            if command not in q:
                q.append(command)
                line = ",".join(q)
                self.queuefile.write_text(line)
        lock.unlockfile()

    def processq(self):
        """ Process any queued commands

        Use hard lock to ensure sole access to queuefile
        """

        while True:
            command = None
            lock = Locker(str(self.qlockfile))
            if lock.lockfile():
                if self.queuefile.exists():
                    line = self.queuefile.read_text()
                    q = line.split(',')
                    if any(q):
                        command = q.pop(0)
                        # remember q has now changed
                        if not any(q):
                            self.queuefile.unlink()
                        else:
                            line = ",".join(q)
                            self.queuefile.write_text(line)
            lock.unlockfile()

            if command:
                self.execute(command)
            else:
                break

    def execute(self, command):
        """ Execute a command """

        # pylint: disable=too-many-branches

        cf = self.cf

        if command == 'load':
            fw_manage(cf)

        elif command == 'whitelist':
            from .whitelist import WhiteList
            wt = WhiteList(cf)
            changes = wt.whitelist()
            # rebuild the firewall if needed
            if changes > 0:
                self.enqueue('load')

        elif command == 'blacklist':
            bl = BlackList(cf)
            # overload -x flag to do a scan for
            # blacklist
            if self.cf.create_build_only:
                bl.blacklist_scan()
            else:
                changes = bl.blacklist()
                # rebuild the firewall if needed
                if changes > 0:
                    self.enqueue('load')

        elif command == 'tidy':
            bl = BlackList(cf)
            bl.clean_database()

        elif command == 'clean':
            from .fwcmds import fw_clean
            fw_clean(cf)

        elif command == 'save':
            from .fwcmds import fw_save
            fw_save(cf)

        elif command == 'restore':
            from .fwcmds import fw_restore
            fw_restore(cf)

        elif command == 'edit':
            # args to fns stored in cf
            from .nf_edit_dbfns import DbFns
            dbf = DbFns(cf)
            changes = dbf.execute()
            if changes > 0:
                self.enqueue('load')
