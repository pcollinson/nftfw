The Makefile here is intended to run tests and pylint3 on the sources.

You may need to install pytest-3 and pylint3

apt install python3-pytest
apt install pylint3

Running

$ make

will run the init_tests.py to create the necessary reference files
and will then run all the tests. It copies files from the data
directory into a new directory called sys - which mimics the
system files. Two working directories are also created for
the tests to use - srcdata and newdata. All of these new files
are deleted in the last test or can be deleted by

$ make clean

If you are using git to get updates, then it may be wise to

$ make clean

afterwards so that you don't have any changed files, otherwise git will
complain when you run 'git pull' to update things.

You can use
$ make lint
to run pylint on all the sources, or for example
$ make configsetup.lint
will run pylint on configsetup.py


Notes on the tests
------------------

Tests need to be run from this directory, they try hard not to zap any
settings that you have stored on the live system. The data directory
contains the files that are needed in the sys directory for the tests
to run. The init_tests.py module creates the necessary directories:
   sys
   srcdata
   newdata
and will need running by hand if you are running single tests. This
can be run using make - see below. The final test test_99_cleanall.py cleans up after the sequence
has been run.

The tests use a sample setup living in the 'sys' directory and specifically a
'config.ini' file that should supersede compiled in default settings.

Several tests compare program output with static data files living in
'srcdata', if the contents of 'sys' are changed, this can make tests
break.

Tests that use stored data will also create a new file in 'newdata'
when they run. The relevant file can be copied to 'data' so that
the next run will be using the correct comparison data. Alternatively,

$ make init

can be used to create the files.

Some things cannot be tested - for example, the current nftables on
the system are not touched.

The blacklist test has a 2 second delay so it can check that
timestamps move on.
