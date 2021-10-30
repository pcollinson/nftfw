# Makefile for tests
SRC = $(sort $(wildcard *.py))
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

.PHONY: lint

all:
	@if /bin/test '${PYLINT}' = '' ; then echo 'Please install pylint(bullseye) or pylint3(buster)'; exit 1; fi
	PYTHONPATH="../nftfw" pytest-3 -x

# create reference files
init:
	python3 init_tests.py

lint: $(OUT)

%.lint: %.py
	@if /bin/test '${PYLINT}' = '' ; then echo 'Please install pylint(bullseye) or pylint3(buster)'; exit 1; fi
	cd ..; ${PYLINT} --exit-zero --rcfile tests/pylintrc -s n --disable=redefined-outer-name tests/$<

clean:
	rm -rf srcdata newdata sys
