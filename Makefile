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
	@echo "  report     regenerate reports/env-report.md and docs/determinism.md from env/gate0.json"
	@echo "  lock       write env/versions.lock from the current environment"
	@echo "  pack       build p0-artifacts.zip (env/, reports/, docs/, raw check logs)"

env-check:
	@mkdir -p env/checks logs reports
	$(PYTHON) $(CHECKS)/run_all.py
	@$(MAKE) --no-print-directory lock
	@$(PYTHON) $(CHECKS)/run_all.py --report-only

report:
	$(PYTHON) $(CHECKS)/render_report.py
	$(PYTHON) $(CHECKS)/render_determinism.py

# Full freeze of the environment the checks actually ran in.
#
# A silently empty lock file is worse than no lock file: the reproducibility
# claim in the report becomes false and nothing surfaces it. So the result is
# staged, then validated -- it must contain torch and more than 10 entries --
# and the target fails loudly if it does not.
lock:
	@mkdir -p env
	@( uv pip freeze --python $(PYTHON) 2>/dev/null \
	   || $(PYTHON) -m pip freeze --all 2>/dev/null ) > env/versions.lock.tmp || true
	@lines=$$(wc -l < env/versions.lock.tmp | tr -d ' '); \
	 if [ "$$lines" -lt 10 ]; then \
	   echo "ERROR: freeze of $(PYTHON) produced $$lines entries (need > 10)"; \
	   rm -f env/versions.lock.tmp; exit 1; \
	 fi; \
	 if ! grep -qiE '^torch([=@ ]|$$)' env/versions.lock.tmp; then \
	   echo "ERROR: freeze does not contain torch -- wrong interpreter?"; \
	   rm -f env/versions.lock.tmp; exit 1; \
	 fi; \
	 mv env/versions.lock.tmp env/versions.lock; \
	 echo "wrote env/versions.lock ($$lines packages, torch present)"

# docs/ and logs/ are created first so zip does not warn on a fresh checkout
# where no check has run yet.
pack: clean-artifacts
	@mkdir -p env reports docs logs
	@touch logs/.keep
	@zip -q -r p0-artifacts.zip env reports docs logs \
	   -x '*/__pycache__/*' '*.pyc'
	@echo "wrote p0-artifacts.zip"
	@unzip -l p0-artifacts.zip | tail -3

clean-artifacts:
	@rm -f p0-artifacts.zip
