# Makefile for pylint
# NB Now needs gnumake
# Distinct files are taken from PackageIndex.py
# Called with no arguments, runs pylint on all files,
# 	then mypy on the package
# make lint - runs pylint on all files
# make filename.lint - runs lint on that file
# make mypy - runs mypy on all files
# make filename.mypy - runs mypy on named file

SRC = $(sort $(filter-out PackageIndex.py,$(wildcard *.py)))
OUT = $(sort $(SRC:.py=.lint))
OUTM = $(sort $(SRC:.py=.mypy))

# Assume that this machine only has python3
PYLINT = pylint
MYPY = mypy

phony: lint

all: $(SRC)
	cd ..; $(PYLINT) --rcfile nftfw/pylintrc --exit-zero -s n nftfw/$<
	cd ..; $(MYPY) nftfw

lint: ${OUT}

%.lint: %.py
	cd ..; $(PYLINT) --rcfile nftfw/pylintrc --exit-zero -s n nftfw/$<

mypy: $(OUTM)
	cd ..; $(MYPY) nftfw

%.mypy: %.py
	cd ..; $(MYPY) nftfw/$<

# pylintrc now ignores 'import-outside-toplevel'. Some nftfw modules selectively import code depending on use.
# and will trigger this on bullseye and later
