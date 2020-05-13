# Makefile for tests
SRC = $(sort $(wildcard *.py))
OUT = $(sort $(SRC:.py=.lint))
REFERENCE = data/build_files.json data/firewallreader.pickle data/listreader-records.json data/logreader.json data/patternreader.pickle data/rulesreader.json data/srcdict.json data/step1_files.json

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
	rm -rf sys/install.d.* sys/build.d/* data/* newdata/*
