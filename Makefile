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

lock:
	@mkdir -p env
	@$(PYTHON) -c "import sys,subprocess;\
	out=subprocess.run([sys.executable,'-m','pip','freeze','--all'],capture_output=True,text=True);\
	sys.stdout.write(out.stdout)" > env/versions.lock 2>/dev/null \
	  || uv pip freeze --python $(PYTHON) > env/versions.lock
	@head -c 0 env/versions.lock; echo "wrote env/versions.lock ($$(wc -l < env/versions.lock) packages)"

pack: clean-artifacts
	@zip -q -r p0-artifacts.zip env reports docs \
	   logs/*.log \
	   -x 'env/checks/.*' '*/__pycache__/*'
	@echo "wrote p0-artifacts.zip"
	@unzip -l p0-artifacts.zip | tail -3

clean-artifacts:
	@rm -f p0-artifacts.zip
