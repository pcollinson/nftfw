
41;2500;0c# Makefile for pylint
# NB Now needs gnumake
SRC = $(sort $(filter-out PackageIndex.py,$(wildcard *.py)))
OUT = $(sort $(SRC:.py=.lint))
# bullseye loses pylint3, replacing it by pylint
PYL = $(shell if [ -x /usr/bin/pylint ]; then echo pylint; else echo ""; fi)
PYL3 = $(shell if [ -x /usr/bin/pylint3 ]; then echo pylint3; else echo ""; fi)
PYLINT =
ifneq (${PYL3},)
	PYLINT = pylint3
else ifneq (${PYL},)
	PYLINT = pylint
endif

all:
	@if /bin/test '${PYLINT}' = '' ; then echo 'Please install pylint(bullseye) or pylint3(buster)'; exit 1; fi
	@echo 'Use the command "make lint" to run lint'

lint: ${OUT}


%.lint: %.py
	@if /bin/test '${PYLINT}' = '' ; then echo 'Please install pylint(bullseye) or pylint3(buster)'; exit 1; fi
	cd ..; ${PYLINT} --rcfile nftfw/pylintrc --exit-zero -s n nftfw/$<

# pylintrc now ignores 'import-outside-toplevel'. Some nftfw modules selectively import code depending on use.
# and will trigger this on bullseye and later
# However, the error is not present in buster's pylint3 and it complains about the disable code because it
# doesn't understand it. So the solution is to remove the inline disable code and make a global option.
#
