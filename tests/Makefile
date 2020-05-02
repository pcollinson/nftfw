# Makefile for tests
SRC = $(sort $(wildcard *.py))
OUT = $(sort $(SRC:.py=.lint))

.PHONY: all init lint

all:
	pytest-3

init:
	python3 init_tests.py

lint: $(OUT)

%.lint: %.py
	PYTHONPATH=./nftfw pylint3 --exit-zero -s n --disable=redefined-outer-name $<

clean:
	rm -rf sys/install.d.* sys/build.d/* data/* newdata/*
