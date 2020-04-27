"""nftfw sqlite3 database management to store file read positions

Database schema
---------------
file : str
    Path to file (primary unique key)
linesig : str
    Hash of first line of file
    used to tell if file has changed
posn : str
    Current seek position in file
ts : int
    Unix timestamp of last operation
"""

import time
import logging
from sqdb import SqDb
log = logging.getLogger('nftfw')

class FileposDb(SqDb):
    """Manages the file position information

    Superclass: SqDb for sqlite3 API
    """

    def __init__(self, cf, createdb=True):
        """Initialise and create database if needed

        Parameters
        ----------
        cf : Config
        createdb : bool
            Create database control, if false
            assume database is present
        """

        create = """CREATE TABLE filepos
                    (file TEXT PRIMARY KEY, linesig TEXT, posn INT, ts INT);
                    CREATE UNIQUE INDEX filepos_ix ON filepos(file);
                 """
        path = cf.varfilepath('filepos')
        if createdb:
            super().__init__(cf, path, {'filepos':create})
        else:
            super().__init__(cf, path, None)

    def getfileinfo(self, file):
        """Get information from the database on file

        Parameters
        ----------
        file : str
            Full path to file

        Returns
        -------
        tuple
            int
                Current position
            str
                String of line signature
        """

        ans = self.lookup('filepos', what='posn,linesig',
                          key='file', val=file)
        if ans is None or not any(ans):
            return (0, None)
        return (ans[0]['posn'], ans[0]['linesig'])

    def setfileinfo(self, file, posn, linesig):
        """Use replace to insert a record in database

        Parameters
        ----------
        file : str
            Full path to file
        posn : int
            File offset
        linesig : str
            Hash of first line
        """

        args = {'file': file,
                'posn': posn,
                'linesig': linesig,
                'ts': int(time.time())}
        self.replace('filepos', args)
