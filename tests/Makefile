# Makefile for tests
# make will run all tests
# make filename.test will run one test
# make lint will run pylint on all files
# make filename.lint runs pylint on the file

SRC = $(sort $(wildcard *.py))
OUT = $(sort $(SRC:.py=.lint))
OUTM = $(sort $(SRC:.py=.mypy))

# Assume that this machine only has python3
PYLINT = pylint
PYTEST = pytest
MYPY = mypy

.PHONY: lint test

all:
	PYTHONPATH="../nftfw" ${PYTEST} -x

# create reference files
init:
	python3 init_tests.py

lint: $(OUT)

%.lint: %.py
	cd ..; ${PYLINT} --exit-zero --rcfile tests/pylintrc -s n --disable=redefined-outer-name tests/$<

%.test: %.py
	PYTHONPATH="../nftfw" ${PYTEST} -x $<

mypy: $(OUTM)
	cd ..; $(MYPY) tests

%.mypy: %.py
	cd ..; $(MYPY) tests/$<

clean:
	rm -rf srcdata newdata sys
