.PHONY: test demo serve fixtures count

PYTHON ?= python
NOW ?= 2024-01-01T00:00:00Z

test:
	$(PYTHON) -m pytest -q

demo:
	$(PYTHON) -m decodebench pipeline --config configs/demo.yml --now $(NOW)

serve:
	$(PYTHON) -m decodebench serve --config configs/demo.yml

fixtures:
	$(PYTHON) scripts/gen_fixtures.py

count:
	$(PYTHON) scripts/count_lines.py
