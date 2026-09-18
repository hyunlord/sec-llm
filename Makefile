# P0 environment verification gate.
#
# Everything here is expected to run on the DGX Spark (GB10, aarch64, CUDA 13).
# PYTHON defaults to the project venv; override it if you keep the environment
# somewhere else:  make env-check PYTHON=/path/to/python

PYTHON ?= .venv/bin/python
CHECKS := scripts/env_check

.DEFAULT_GOAL := help
.PHONY: help env-check report lock pack clean-artifacts

help:
	@echo "targets:"
	@echo "  env-check  run checks 01..08, write env/gate0.json, regenerate reports/env-report.md"
	@echo "  report     regenerate reports/env-report.md from the existing env/gate0.json"
	@echo "  lock       write env/versions.lock from the current environment"
	@echo "  pack       build p0-artifacts.zip (env/, reports/, docs/, raw check logs)"

env-check:
	@mkdir -p env/checks logs reports
	$(PYTHON) $(CHECKS)/run_all.py
	@$(MAKE) --no-print-directory lock
	@$(PYTHON) $(CHECKS)/run_all.py --report-only

report:
	$(PYTHON) $(CHECKS)/render_report.py

# Full freeze of the environment the checks actually ran in. uv is the
# installer here, so it is the primary source; pip is the fallback for an
# environment built some other way. An empty result is an error, not a lock
# file -- silently shipping one would make `make env-check` unreproducible.
lock:
	@mkdir -p env
	@( uv pip freeze --python $(PYTHON) 2>/dev/null \
	   || $(PYTHON) -m pip freeze --all 2>/dev/null ) > env/versions.lock.tmp
	@if [ ! -s env/versions.lock.tmp ]; then \
	  rm -f env/versions.lock.tmp; \
	  echo "ERROR: could not freeze $(PYTHON) -- no packages listed"; exit 1; \
	fi
	@mv env/versions.lock.tmp env/versions.lock
	@echo "wrote env/versions.lock ($$(wc -l < env/versions.lock) packages)"

pack: clean-artifacts
	@zip -q -r p0-artifacts.zip env reports docs \
	   logs/*.log \
	   -x 'env/checks/.*' '*/__pycache__/*'
	@echo "wrote p0-artifacts.zip"
	@unzip -l p0-artifacts.zip | tail -3

clean-artifacts:
	@rm -f p0-artifacts.zip
