ifeq ($(OS),Windows_NT)
PYTHON ?= py -3
else
PYTHON ?= python3
endif

.DEFAULT_GOAL := run
.PHONY: build run test

build:
	$(PYTHON) build.py

run: build
	$(PYTHON) main.py

test: build
	$(PYTHON) -m unittest discover -s tests -v
