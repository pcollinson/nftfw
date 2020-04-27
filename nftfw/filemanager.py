"""nftfw FileManager class

Provides caching for filesystem operations
"""

import logging
log = logging.getLogger('nftfw')


class FileManager:
    """FileManager class
    Ensure that all files are written/deleted quickly to assist
    incron calls to the firewall.

    Cache files and contents, and call them all in a loop later
    """

    def __init__(self, cf):
        """Initialise storage

        Parameters
        ----------
        cf : Config
        """

        self.cf = cf
        # files to be written
        self.files = []
        # files to be touched
        self.touchfiles = []
        # files to be deleted
        self.deletefiles = []

    def write(self, filepath, contents):
        """Write data to file

        Store values in files list

        Parameters
        ----------
        filepath : Path
            Path to file to be written
        contents : str
            File contents
        """

        values = (filepath, contents)
        self.files.append(values)

    def touch(self, filepath):
        """Touch a file

        Store values in touchfiles list

        Parameters
        ----------
        filepath : Path
            Path to file to be touched
        """

        self.touchfiles.append(filepath)

    def delete(self, filepath):
        """Delete a file

        Store in deletefiles list

        Parameters
        ----------
        filepath : Path
            Path to file to be deleted
        """

        self.deletefiles.append(filepath)


    def action(self):
        """Action the files, touch and delete lists
        to change the filesystem

        Three lists hold Path objects
        """
        cf = self.cf

        for f in self.touchfiles:
            f.touch()
            cf.chownpath(f)

        for f, c in self.files:
            f.write_text(c)
            cf.chownpath(f)

        for f in self.deletefiles:
            f.unlink()

        # allow reentrancy
        self.touchfiles = []
        self.files = []
        self.deletefiles = []
