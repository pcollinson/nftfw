# Makefile for tests
SRC = $(sort $(wildcard *.py))
OUT = $(sort $(SRC:.py=.lint))

all:
	pytest-3

lint: $(OUT)

%.lint: %.py
	PYTHONPATH=./nftfw pylint3 --exit-zero -s n --disable=redefined-outer-name $<
