# Makefile for pylint
SRC = $(sort $(filter-out PackageIndex.py,$(wildcard *.py)))
OUT = $(sort $(SRC:.py=.lint))

all:
	echo 'Use make lint to run lint'
	cat PackageIndex.py

lint: $(OUT)

%.lint: %.py
	pylint3 --exit-zero -s n $<
