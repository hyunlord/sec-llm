# P0 environment verification gate.
#
# Everything here is expected to run on the DGX Spark (GB10, aarch64, CUDA 13).
# PYTHON defaults to the project venv; override it if you keep the environment
# somewhere else:  make env-check PYTHON=/path/to/python

PYTHON ?= .venv/bin/python
CHECKS := scripts/env_check

.DEFAULT_GOAL := help
.PHONY: help env-check report lock pack clean-artifacts pin ingest ingest-offline ingest-verify sources-doc ingest-report process calibrate process-report datasets contamination datasets-docs

help:
	@echo "targets:"
	@echo "  env-check  run checks 01..08, write env/gate0.json, regenerate reports/env-report.md"
	@echo "  report     regenerate reports/env-report.md and docs/determinism.md from env/gate0.json"
	@echo "  lock       write env/versions.lock from the current environment"
	@echo "  pack       build p0-artifacts.zip (env/, reports/, docs/, raw check logs)"
	@echo ""
	@echo "  pin           resolve every source to an immutable reference -> ingest/sources.lock.json"
	@echo "  ingest        ingest every pinned source -> manifests/<source>.manifest.json"
	@echo "  ingest-verify re-run ingest and prove the manifests are byte-identical"
	@echo "  ingest-offline re-run ingest with the network forbidden; proves offline reproducibility"
	@echo "  sources-doc   regenerate docs/data-sources.md from ingest/sources.py"
	@echo "  ingest-report regenerate reports/ingest.md from the manifests"
	@echo ""
	@echo "  process       run P2: canonicalize, dedup, identity, secrets -> process.manifest.json"
	@echo "  calibrate     re-run the near-duplicate threshold sweep against the labelled sample"
	@echo "  process-report regenerate the three P2 Korean reports"
	@echo ""
	@echo "  datasets      P3: extract, build tasks+splits+replay, contamination, lengths, manifest, docs"
	@echo "  contamination re-run the n-gram overlap check; add ARGS=--assert-zero to fail on any overlap"
	@echo "  datasets-docs regenerate the P3 Korean docs and reports from the manifest"

# Rule 1 is enforced by the environment, not by intent. PIP_ONLY_BINARY makes
# pip refuse a source distribution at resolution time rather than starting a
# compile on a machine where a compile can take the whole host down.
export PIP_ONLY_BINARY := :all:
export UV_NO_BUILD := 1
export PIP_CONFIG_FILE := $(CURDIR)/pip.conf

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
# GATE0 is overridable only so the refusal can be proven against a fixture:
#   make pack GATE0=tests/fixtures/gate0.fixture.json   -> must fail
GATE0 ?= env/gate0.json

pack: clean-artifacts
	@mkdir -p env reports docs logs
	@$(INGEST_PY) tools/pack_guard.py $(GATE0)
	@touch logs/.keep
	@zip -q -r p0-artifacts.zip env reports docs logs \
	   -x '*/__pycache__/*' '*.pyc'
	@echo "wrote p0-artifacts.zip"
	@unzip -l p0-artifacts.zip | tail -3

clean-artifacts:
	@rm -f p0-artifacts.zip

# ---------------------------------------------------------------------------
# P1 -- source ingestion
#
# INGEST_PY is separate from PYTHON: ingestion is stdlib-only and runs on the
# local machine as well as on the DGX, where PYTHON points at the CUDA venv.
# PIP_ONLY_BINARY is exported per rule 1 carried over from P0.1 -- nothing in
# this project compiles from source on a machine we care about.
INGEST_PY ?= python3
export PIP_ONLY_BINARY := :all:

pin:
	$(INGEST_PY) ingest/pin.py $(PIN_ARGS)

ingest:
	$(INGEST_PY) ingest/run.py $(INGEST_ARGS)

# Gate 2 condition 8. SEC_LLM_OFFLINE makes any attempted network call raise, so
# a manifest that reproduces here reproduced from retained local artifacts and
# nothing else. "It reproduced" and "it reproduced without touching the network"
# are different claims and only the second one is worth much.
ingest-offline:
	@mkdir -p manifests
	@shasum -a 256 manifests/*.json > /tmp/sec-llm-off1.txt
	SEC_LLM_OFFLINE=1 $(INGEST_PY) ingest/run.py $(INGEST_ARGS)
	@shasum -a 256 manifests/*.json > /tmp/sec-llm-off2.txt
	@if diff -u /tmp/sec-llm-off1.txt /tmp/sec-llm-off2.txt; then \
	  echo "MANIFESTS REPRODUCIBLE OFFLINE"; \
	else \
	  echo "ERROR: manifests changed when re-derived offline"; exit 1; \
	fi

# Gate 1 requirement 2: re-running against the same pins must reproduce the
# manifests byte for byte. Hash, re-run, hash, diff -- and fail if they differ.
ingest-verify:
	@mkdir -p manifests
	@shasum -a 256 manifests/*.json > /tmp/sec-llm-m1.txt
	$(INGEST_PY) ingest/run.py $(INGEST_ARGS)
	@shasum -a 256 manifests/*.json > /tmp/sec-llm-m2.txt
	@if diff -u /tmp/sec-llm-m1.txt /tmp/sec-llm-m2.txt; then \
	  echo "MANIFESTS REPRODUCIBLE"; \
	else \
	  echo "ERROR: manifests changed across runs against the same pins"; exit 1; \
	fi

sources-doc:
	$(INGEST_PY) ingest/render_sources_doc.py

ingest-report:
	$(INGEST_PY) ingest/render_report.py

process:
	$(INGEST_PY) -m process.run
	$(INGEST_PY) -m process.render_reports

calibrate:
	$(INGEST_PY) -m process.calibrate

process-report:
	$(INGEST_PY) -m process.render_reports

# P3 -- dataset construction. Order matters: the manifest is written last, from
# the final artifacts, after contamination removal and length profiling.
datasets:
	$(INGEST_PY) -m datasets.extract
	$(INGEST_PY) -m datasets.build
	$(INGEST_PY) -m datasets.contamination
	$(INGEST_PY) -m datasets.contamination --assert-zero
	$(INGEST_PY) -m datasets.lengths
	$(INGEST_PY) -m datasets.manifest
	$(INGEST_PY) -m datasets.render_docs

contamination:
	$(INGEST_PY) -m datasets.contamination $(ARGS)

datasets-docs:
	$(INGEST_PY) -m datasets.render_docs
