"""nftfw work scheduler.

This module provides the Scheduler class which coordinates the execution of
nftfw commands using file-based locking to prevent concurrent operations.

The scheduler implements two distinct execution modes:
1. System commands: Automatically triggered commands (load, whitelist, blacklist,
   tidy) that use non-blocking locks and queue when lock is unavailable.
2. User commands: Interactive commands (clean, flush, save, restore, edit) that
   wait for the lock to become available.

System commands process the command queue after execution to catch up on any
queued operations, ensuring no work is lost even under high load.

Example:
    Basic usage via command-line entry point::

        from .config import Config
        from .scheduler import Scheduler

        cf = Config()
        scheduler = Scheduler(cf)
        scheduler.run('load')  # Execute firewall load command

Note:
    The scheduler uses three lock/queue files in the sysvar directory:
    - sched.lock: Main scheduler lock to prevent concurrent execution
    - sched.queue: Queue file storing comma-separated command list
    - queue.lock: Separate lock for thread-safe queue access
"""
from __future__ import annotations
from typing import TYPE_CHECKING, cast
from pathlib import Path
from .locker import Locker
from .fwmanage import fw_manage
from .blacklist import BlackList

if TYPE_CHECKING:
    from .config import Config

#pylint: disable=import-outside-toplevel

class Scheduler:
    """Command scheduler with file-based locking and queueing.

    The Scheduler class manages execution of nftfw commands, ensuring only one
    command runs at a time through file-based locking. It provides intelligent
    queueing for automated system commands and blocking behaviour for interactive
    user commands.

    Attributes:
        wait: Class-level list of user commands that must wait for lock.
            These commands (clean, flush, save, restore, edit) are typically
            invoked interactively and should block until resources are available.
        cf: Config instance containing all configuration settings.
        lockfile: Path to main scheduler lock file (sched.lock).
        queuefile: Path to queue file storing pending commands (sched.queue).
        qlockfile: Path to queue lock file for thread-safe queue access (queue.lock).

    Note:
        The class uses dynamic imports (import-outside-toplevel) to avoid loading
        unused modules. This is intentional and disabled in pylint configuration.

    Example:
        Creating and using a scheduler::

            cf = Config()
            sched = Scheduler(cf)
            sched.run('blacklist')  # Will queue if lock unavailable
            sched.run('clean')      # Will wait for lock to become available
    """

    # List of 'user' tasks that wait for lock availability
    # 'edit' refers to the nftfwedit command
    wait: list[str] = ['clean', 'flush', 'save', 'restore', 'edit']

    def __init__(self, cf: Config) -> None:
        """Initialize the scheduler with lock and queue file paths.

        Sets up the file paths for the main scheduler lock, command queue,
        and queue lock based on the sysvar location from configuration.

        Args:
            cf: Config instance containing system configuration including
                the sysvar directory path.

        Note:
            All lock and queue files are created in the sysvar directory
            (typically /var/lib/nftfw).
        """
        self.cf: Config = cf
        sysvar = Path(cast(str, cf.get_ini_value_from_section('Locations', 'sysvar')))
        self.lockfile: Path = sysvar / 'sched.lock'
        self.queuefile: Path = sysvar / 'sched.queue'
        self.qlockfile: Path = sysvar / 'queue.lock'

    def run(self, command: str) -> None:
        """Execute a command with appropriate locking strategy.

        Determines the execution strategy based on command type and configuration:
        - User commands: Block until lock is available, don't process queue
        - System commands: Use non-blocking lock; queue if unavailable
        - Commands with build_only or specific pattern: Treat as user commands

        The method handles three scenarios:
        1. User command or special flags: Wait for lock, execute, skip queue
        2. System command but lock unavailable: Add to queue
        3. System command with lock acquired: Execute and process queue

        Args:
            command: Command name to execute. Valid commands include:
                System: 'load', 'whitelist', 'blacklist', 'tidy'
                User: 'clean', 'flush', 'save', 'restore', 'edit'

        Note:
            Commands run with create_build_only flag or selected_pattern_file
            are treated as user commands because they are typically invoked
            interactively for testing or debugging specific configurations.
            These commands don't process the queue since they're not part of
            regular automated maintenance - the queue will be processed on the
            next scheduled system command.
        """
        lock = Locker(str(self.lockfile))

        # Treat as user command if:
        # - Command is in the wait list (interactive user commands)
        # - Build-only mode is enabled (testing/debugging)
        # - A specific pattern file is selected (targeted testing)
        if command in self.wait \
           or self.cf.create_build_only \
           or self.cf.selected_pattern_file is not None:
            if lock.lockfile():
                self.execute(command)
                # Don't process queue for user commands
                # Queue will be processed on next timed system action

        elif not lock.nb_lockfile():
            # Non-blocking lock failed, add to queue
            self.enqueue(command)

        else:
            # We acquired the lock, execute command and process queue
            self.execute(command)
            self.processq()

        lock.unlockfile()

    def enqueue(self, command: str) -> None:
        """Add a command to the queue if not already present.

        Uses a separate queue lock file to ensure thread-safe access to the
        queue file. Commands are stored as a comma-separated list with no
        duplicates allowed.

        Args:
            command: Command name to add to the queue. Only one instance
                of each command type is allowed in the queue at a time.

        Note:
            The queue file (sched.queue) contains a comma-separated list of
            pending commands. The separate queue lock (queue.lock) prevents
            race conditions when multiple processes try to modify the queue
            simultaneously.

        Example:
            If queue contains "load,blacklist" and we enqueue "whitelist",
            the queue becomes "load,blacklist,whitelist". Enqueueing "load"
            again would have no effect since it's already present.
        """
        lock = Locker(str(self.qlockfile))
        if lock.lockfile():
            q: list[str] = []
            if self.queuefile.exists():
                line = self.queuefile.read_text()
                q = line.split(',')
            if command not in q:
                q.append(command)
                line = ",".join(q)
                self.queuefile.write_text(line)
        lock.unlockfile()

    def processq(self) -> None:
        """Process all queued commands in FIFO order.

        Continuously processes commands from the queue until empty. Each
        iteration acquires the queue lock, extracts the first command,
        updates or removes the queue file, then executes the command.

        The queue file is removed when the last command is processed,
        otherwise it's updated with the remaining commands.

        Note:
            Uses a blocking lock on the queue file to ensure atomic queue
            operations. Commands are processed in the order they were added
            (first in, first out). Each command execution may itself enqueue
            additional commands (e.g., whitelist/blacklist enqueue 'load'),
            which will be processed in subsequent iterations.

        Example:
            If queue contains "whitelist,blacklist,tidy":
            1. Execute whitelist (may enqueue 'load')
            2. Execute blacklist (may enqueue 'load')
            3. Execute tidy
            4. Execute load (if it was enqueued, only once due to deduplication)
        """
        while True:
            command: str | None = None
            lock = Locker(str(self.qlockfile))
            if lock.lockfile():
                if self.queuefile.exists():
                    line = self.queuefile.read_text()
                    q = line.split(',')
                    if any(q):
                        command = q.pop(0)
                        # q has now changed after pop
                        if not any(q):
                            # Queue is empty, remove file
                            self.queuefile.unlink()
                        else:
                            # Update queue file with remaining commands
                            line = ",".join(q)
                            self.queuefile.write_text(line)
            lock.unlockfile()

            if command:
                self.execute(command)
            else:
                break

    def execute(self, command: str) -> None:
        """Dispatch command to appropriate handler function.

        This is the central command dispatcher that routes each command to its
        implementation. Commands that modify the firewall configuration (whitelist,
        blacklist, edit) automatically enqueue a 'load' command when changes are made.

        Args:
            command: Command name to execute. Valid commands:
                - 'load': Install/update firewall rules
                - 'whitelist': Scan wtmp and update whitelist, enqueue load if changed
                - 'blacklist': Scan logs and update blacklist, enqueue load if changed
                - 'tidy': Clean old entries from blacklist database
                - 'clean': Remove all nftables rules installed by nftfw
                - 'save': Save current nftables rules to backup file
                - 'restore': Restore nftables rules from backup file
                - 'edit': Edit blacklist database entries, enqueue load if changed

        Note:
            Uses dynamic imports to avoid loading unnecessary modules. This is
            particularly important for the command-line tools which may only use
            one or two commands per invocation.

            The create_build_only flag overloads the blacklist command to perform
            a scan-only operation without updating the database or firewall.
        """
        # pylint: disable=too-many-branches

        cf = self.cf

        if command == 'load':
            fw_manage(cf)

        elif command == 'whitelist':
            from .whitelist import WhiteList
            wt = WhiteList(cf)
            changes = wt.whitelist()
            # Rebuild the firewall if whitelist changed
            if changes > 0:
                self.enqueue('load')

        elif command == 'blacklist':
            bl = BlackList(cf)
            # The -x flag is overloaded to perform scan-only mode for blacklist
            if self.cf.create_build_only:
                bl.blacklist_scan()
            else:
                changes = bl.blacklist()
                # Rebuild the firewall if blacklist changed
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
            # Command arguments stored in cf (Config instance)
            from .nf_edit_dbfns import DbFns
            dbf = DbFns(cf)
            changes = dbf.execute()
            # Rebuild the firewall if database was modified
            if changes > 0:
                self.enqueue('load')
