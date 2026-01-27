The Makefile here is intended to run pylint and mypy and on the
sources, it assumes that you are running on a system which only
has a single version of python installed.

You may need to install pylint or mypy

apt install python3-pylint
apt install mypy

Then
When Called with no arguments, runs pylint on all files,
 	then mypy on the package
make lint - runs pylint on all files
make filename.lint - runs lint on that file
make mypy - runs mypy on all files
make filename.mypy - runs mypy on named file
