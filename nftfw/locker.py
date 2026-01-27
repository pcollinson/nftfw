#!/usr/bin/env python
"""File-based locking mechanism for nftfw.

This module provides a simple file-based locking mechanism to ensure mutual
exclusion when multiple nftfw processes might run concurrently. It supports
both blocking and non-blocking lock acquisition.

Example usage:
    # Basic usage with manual lock/unlock
    lock = Locker('/var/lib/nftfw/sched.lock')
    if lock.lockfile():
        try:
            # Do protected work
            pass
        finally:
            lock.unlockfile()

    # Preferred usage with context manager
    with Locker('/var/lib/nftfw/sched.lock') as lock:
        if lock:
            # Do protected work
            pass

The Locker uses fcntl.flock() which provides advisory locking at the file
descriptor level. Locks are automatically released when the file descriptor
is closed or the process terminates.
"""

from __future__ import annotations

import sys
import fcntl
import logging
from typing import IO, Optional

log = logging.getLogger('nftfw')



class Locker:
    """File-based lock manager using fcntl.flock().

    This class provides exclusive file locking capabilities with both blocking
    and non-blocking modes. It can be used as a context manager for automatic
    lock cleanup.

    Attributes:
        filename: Path to the lock file.
        fd: Open file descriptor for the lock file, or None if not locked.

    Example:
        >>> lock = Locker('/var/run/myapp.lock')
        >>> if lock.nb_lockfile():  # Try non-blocking lock
        ...     try:
        ...         # Critical section
        ...         pass
        ...     finally:
        ...         lock.unlockfile()
    """

    def __init__(self, filename: str) -> None:
        """Initialize the Locker with a lock file path.

        Args:
            filename: Path to the file to use for locking. The file will be
                created if it doesn't exist. Parent directory must exist.
        """
        self.filename = filename
        self.fd: Optional[IO[str]] = None

    def lockfile(self) -> bool:
        """Acquire an exclusive lock, blocking until available.

        This method will block indefinitely until the lock can be acquired.
        If the lock file cannot be opened opened for writing, will kill the
        application using the code.

        Returns:
            True if the lock was successfully acquired.
            False on errors
        Note:
            The lock is automatically released when unlockfile() is called,
            when the file descriptor is closed, or when the process exits.
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


    def nb_lockfile(self) -> bool:
        """Attempt to acquire an exclusive lock without blocking.

        This method attempts to acquire the lock immediately. If the lock
        is already held by another process, it returns False immediately
        rather than waiting.

        Returns:
            True if the lock was successfully acquired, False if the lock
            is currently held by another process.

            Will exit the system if the lock file cannot be opened
            for writing

        Example:
            >>> lock = Locker('/tmp/myapp.lock')
            >>> if lock.nb_lockfile():
            ...     print("Got the lock!")
            ...     lock.unlockfile()
            ... else:
            ...     print("Lock is busy")
        """
        # pylint: disable=consider-using-with
        try:
            self.fd = open(self.filename, 'w+')
        except IOError as e:
            error_msg = f'Cannot open lock file {self.filename}: {e}'
            log.error('Fatal error: %s', error_msg)
            sys.exit(1)
        try:
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except IOError:
            return False

    def unlockfile(self) -> None:
        """Release the lock and close the lock file.

        This method releases the exclusive lock if held and closes the file
        descriptor. It is safe to call this method multiple times or when
        no lock is held.

        Note:
            After calling this method, the Locker can be reused to acquire
            the lock again by calling lockfile() or nb_lockfile().
        """
        if self.fd:
            try:
                fcntl.flock(self.fd, fcntl.LOCK_UN)
            except IOError as e:
                log.warning('Error unlocking %s: %s', self.filename, e)
            finally:
                self.fd.close()
                self.fd = None

    def __enter__(self) -> Locker:
        """Enter context manager - acquire blocking lock.

        Returns:
            Self, with lock acquired.

        """
        self.lockfile()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Exit context manager - release lock.

        Args:
            exc_type: Exception type if an exception occurred, None otherwise.
            exc_val: Exception value if an exception occurred, None otherwise.
            exc_tb: Exception traceback if an exception occurred, None otherwise.
        """
        self.unlockfile()

    def __del__(self) -> None:
        """Destructor - ensure lock is released when object is garbage collected."""
        self.unlockfile()
