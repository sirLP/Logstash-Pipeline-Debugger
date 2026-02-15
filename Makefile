VENV := venv
PYTHON := $(VENV)/bin/python
PIP := $(VENV)/bin/pip

.PHONY: venv install run test clean

venv:
	python3 -m venv $(VENV)

install: venv
	$(PYTHON) -m pip install --upgrade pip setuptools wheel
	$(PIP) install -r requirements.txt

run: install
	$(PYTHON) app.py

test: install
	$(VENV)/bin/pytest -q

clean:
	rm -rf build dist *.egg-info $(VENV) .pytest_cache __pycache__
