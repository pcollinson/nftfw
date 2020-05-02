The Makefile here is intended to run pylint3 on the sources.

You may need to install pylint3

apt install python3-pylint

Then

make lint

will run lint on all the sources, or for example

make fwdb.lint

will run lint on fwdb.py
