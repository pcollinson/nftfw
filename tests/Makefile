# Makefile for tests
SRC = $(sort $(wildcard *.py))
OUT = $(sort $(SRC:.py=.lint))
REFERENCE = srcdata/build_files.json srcdata/firewallreader.pickle srcdata/listreader-records.json srcdata/logreader.json srcdata/patternreader.pickle srcdata/rulesreader.json srcdata/srcdict.json srcdata/step1_files.json

.PHONY: lint

all: $(REFERENCE)
	pytest-3 -x

$(REFERENCE):
	python3 init_tests.py

init:
	python3 init_tests.py

lint: $(OUT)

%.lint: %.py
	PYTHONPATH=./nftfw pylint3 --exit-zero -s n --disable=redefined-outer-name $<

clean:
	rm -rf srcdata newdata sys
