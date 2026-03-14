PYTHON ?= python3
VENV_DIR ?= .venv
VENV_PYTHON := $(VENV_DIR)/bin/python
REQUIREMENTS := requirements.txt

.PHONY: venv install check run interop-test interop-test-negative

venv:
	$(PYTHON) -m venv $(VENV_DIR)

install: venv
	$(VENV_PYTHON) -m pip install -r $(REQUIREMENTS)

check: install
	$(VENV_PYTHON) -m py_compile pkix_evidence_der.py create_ak.py

run: install
	$(VENV_PYTHON) pkix_evidence_der.py

interop-test: install
	../tools/test-interop.sh

interop-test-negative: install
	../tools/test-interop-negative.sh
