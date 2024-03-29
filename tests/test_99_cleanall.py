""" Tidy up to make things re-entrant """

from pathlib import Path
from shutil import rmtree

def test_clean():
    """ Clean the src data and newdata directories
    to make things re-entrant """

    for deldir in ["srcdata", "newdata"]:
        path = Path(deldir)
        for name in path.glob("*.json"):
            name.unlink()
        for name in path.glob("*.pickle"):
            name.unlink()
        path.rmdir()

    rmtree("sys")
