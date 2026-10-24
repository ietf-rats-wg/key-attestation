PYTHON ?= python3
VENV_DIR ?= .venv
VENV_PYTHON := $(VENV_DIR)/bin/python
REQUIREMENTS := requirements.txt

.PHONY: venv install check run interop-test interop-test-negative

venv:
	$(PYTHON) -m venv $(VENV_DIR)

install: venv
	$(VENV_PYTHON) -m pip install -r $(REQUIREMENTS)

check:
	$(VENV_PYTHON) -m unittest discover -s . -p 'test_*.py' -v

run:
	$(VENV_PYTHON) main.py --help

interop-test:
	PYTHON_BIN="$(abspath $(VENV_PYTHON))" ../tools/test-interop.sh

interop-test-negative:
	PYTHON_BIN="$(abspath $(VENV_PYTHON))" ../tools/test-interop-negative.sh
