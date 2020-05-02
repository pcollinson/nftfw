The Makefile here is intended to run tests and pylint3 on the sources.

You may need to install pytest-3 and pylint3

apt install python3-pytest
apt install pylint3

The tests need a symlink to the nftfw package, this may not survive
github.

ln -s ../nftfw

will do that.

Then

make

will run the test suite and

make lint

will run pylint on all the sources, or for example

make configsetup.lint

will run pylint on configsetup.py


Notes on the tests
------------------

Tests need to be run from this directory, they try hard not to zap any
settings that you have stored on the live system. The tests use a
sample setup living in the 'sys' directory and specifically a
'config.ini' file that should supersede compiled in default settings.
Tests are designed to be re-entrant, so should leave the 'sys'
directory as they found it.

Several tests compare program output with static data files living in
'data', if the contents of 'sys' are changed, this can make tests break.

Tests that use stored data will also create a new file in 'newdata'
when they run. The relevant file can be copied to 'data' so that
the next run will be using the correct comparison data.

Some things cannot be tested - for example, the current nftables on
the system are not touched.

The blacklist test has a 2 second delay so it can check that
timestamps move on.
