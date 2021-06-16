# Makefile for tests
SRC = $(sort $(wildcard *.py))
OUT = $(sort $(SRC:.py=.lint))

.PHONY: lint

all:
	pytest-3 -x

# create reference files
init:
	python3 init_tests.py

lint: $(OUT)

%.lint: %.py
	PYTHONPATH=../nftfw pylint3 --exit-zero -s n --disable=redefined-outer-name $<

clean:
	rm -rf srcdata newdata sys
