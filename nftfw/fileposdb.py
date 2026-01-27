"""File position tracking database for incremental log scanning.

This module provides the FileposDb class, which manages the SQLite database
that tracks read positions in log files. This allows nftfw to incrementally
scan logs without re-reading previously processed content.

The database stores:
- File path (unique identifier)
- Current byte offset in the file
- Hash of the first line (to detect file rotation/replacement)
- Timestamp of last update

Key Features
------------
- Incremental log scanning (resume from last position)
- File rotation detection via first-line signature
- Automatic timestamp tracking for database maintenance
- Simple get/set interface for file position management

Database Schema
---------------
The 'filepos' table contains the following columns:

file : str
    Full path to the log file (primary key, unique)
linesig : str
    Hash of the first line of the file (used to detect file rotation)
posn : int
    Current byte offset in the file (seek position)
ts : int
    Unix timestamp of last update

Usage Example
-------------
    from .config import Config
    from .fileposdb import FileposDb

    # Initialize configuration and database
    cf = Config()
    db = FileposDb(cf)

    # Get last read position for a log file
    posn, linesig = db.getfileinfo('/var/log/auth.log')
    print(f"Resume reading from byte {posn}")

    # After processing, save new position
    with open('/var/log/auth.log', 'r') as f:
        f.seek(posn)
        # ... process new log lines ...
        new_posn = f.tell()
        db.setfileinfo('/var/log/auth.log', new_posn, linesig)

See Also
--------
sqdb.SqDb : Base class providing SQLite database wrapper
logreader : Module that uses FileposDb for incremental log reading
"""
from __future__ import annotations

from typing import TYPE_CHECKING
import time
import logging
from .sqdb import SqDb

if TYPE_CHECKING:
    from .config import Config

log = logging.getLogger('nftfw')


class FileposDb(SqDb):
    """Manages file position tracking for incremental log scanning.

    This class provides a simple interface to track where nftfw stopped reading
    in each log file, allowing it to resume from the last position rather than
    re-scanning the entire file. It also detects file rotation by storing a
    hash of the first line.

    When a log file is rotated or replaced, the first-line signature will change,
    signaling that the file should be read from the beginning.

    Attributes:
        cf: Config instance for accessing configuration
        dbfile: Path to the SQLite database file (typically filepos.db)
        conn: SQLite connection with Row factory enabled

    Example:
        Track position across log scanning runs::

            from .config import Config
            from .fileposdb import FileposDb

            cf = Config()
            db = FileposDb(cf)

            logfile = '/var/log/auth.log'

            # Get stored position
            posn, old_sig = db.getfileinfo(logfile)

            # Read and process log
            with open(logfile, 'r') as f:
                # Check if file was rotated (first line changed)
                first_line = f.readline()
                new_sig = hash(first_line)
                if new_sig != old_sig:
                    posn = 0  # File rotated, start from beginning

                f.seek(posn)
                for line in f:
                    # Process line...
                    pass

                # Save new position
                db.setfileinfo(logfile, f.tell(), new_sig)

    See Also:
        sqdb.SqDb: Base class for SQLite database operations
        logreader: Module that uses this database for incremental log reading
    """

    def __init__(self, cf: Config, createdb: bool = True) -> None:
        """Initialize the file position database.

        Creates or connects to the filepos database and ensures the schema
        exists. The database file location is determined by the Config instance.

        Args:
            cf: Config instance providing database path and settings
            createdb: If True, create database/tables if they don't exist.
                     If False, assume database exists and skip creation.

        Note:
            The filepos table uses a unique index on the 'file' column to ensure
            each file path appears only once in the database.
        """
        create = """CREATE TABLE filepos
                    (file TEXT PRIMARY KEY, linesig TEXT, posn INT, ts INT);
                    CREATE UNIQUE INDEX filepos_ix ON filepos(file);
                 """
        path = cf.varfilepath('filepos')
        if createdb:
            super().__init__(cf, path, {'filepos': create})
        else:
            super().__init__(cf, path, None)

    def getfileinfo(self, file: str) -> tuple[int, str | None]:
        """Get the stored read position and line signature for a file.

        Retrieves the last known read position and first-line signature from
        the database. If the file has never been processed, returns (0, None)
        to indicate reading should start from the beginning.

        Args:
            file: Full path to the log file

        Returns:
            A tuple containing:
                - posn (int): Byte offset where reading should resume (0 if new file)
                - linesig (str | None): Hash of first line (None if new file)

        Example:
            >>> db = FileposDb(cf)
            >>> posn, sig = db.getfileinfo('/var/log/auth.log')
            >>> if sig is None:
            ...     print("New file, starting from beginning")
            ... else:
            ...     print(f"Resume from byte {posn}")
        """
        ans = self.lookup('filepos', what='posn,linesig',
                          where='file = ?', vals=(file,))
        if ans is None or not any(ans):
            return (0, None)
        return (ans[0]['posn'], ans[0]['linesig'])

    def setfileinfo(self, file: str, posn: int, linesig: str) -> int:
        """Store the current read position and line signature for a file.

        Updates or inserts the file position information in the database.
        The timestamp is automatically set to the current time.

        This method uses SQLite's REPLACE operation, which will insert a new
        record if the file doesn't exist, or update the existing record if it does.

        Args:
            file: Full path to the log file
            posn: Current byte offset in the file (from file.tell())
            linesig: Hash or signature of the first line of the file

        Returns:
            The rowid of the inserted/replaced row

        Example:
            >>> import hashlib
            >>> db = FileposDb(cf)
            >>> with open('/var/log/auth.log', 'r') as f:
            ...     first_line = f.readline()
            ...     sig = hashlib.md5(first_line.encode()).hexdigest()
            ...     # ... process file ...
            ...     db.setfileinfo('/var/log/auth.log', f.tell(), sig)

        Note:
            The timestamp (ts) is automatically set to int(time.time()) and
            should not be provided by the caller.
        """
        args = {'file': file,
                'posn': posn,
                'linesig': linesig,
                'ts': int(time.time())}
        return self.replace('filepos', args)
