# Prompt-Injection Tripwire -- common tasks.
# `make bench` runs locally if the Python deps are importable, otherwise inside Docker.

PY ?= $(shell [ -x .venv/bin/python ] && echo .venv/bin/python || echo python3)
COMPOSE ?= docker compose

.PHONY: help install corpus dataset train test bench bench-local bench-docker report demo up down proxy attacker dashboard clean

help:
	@echo "make install      create .venv and install requirements"
	@echo "make test         run pytest (unit, hypothesis fuzzing, end-to-end)"
	@echo "make bench        run the on/off benchmark -> results/report.md"
	@echo "make bench-docker run the benchmark inside Docker against the compose stack"
	@echo "make demo         print agent traces for one benign and one attack scenario"
	@echo "make up / down    docker compose up -d / down"
	@echo "make train        (re)train the classifier; make corpus regenerates the JSONL corpus"

install:
	python3 -m venv .venv && .venv/bin/pip install -q --upgrade pip && .venv/bin/pip install -q -r requirements.txt

corpus:
	$(PY) -m attacks.build_corpus

dataset:
	$(PY) -m classifier.build_dataset --with-public

train:
	$(PY) -m classifier.train

test:
	$(PY) -m pytest -q

bench:
	@if $(PY) -c "import fastapi, rapidfuzz, sklearn, sqlmodel, matplotlib" 2>/dev/null; then \
		$(MAKE) --no-print-directory bench-local; \
	elif command -v docker >/dev/null 2>&1; then \
		echo "[make] Python deps not found locally -> running the benchmark in Docker"; \
		$(MAKE) --no-print-directory bench-docker; \
	else echo "Install deps (make install) or Docker first."; exit 1; fi

bench-local:
	$(PY) -m eval.run_benchmark

bench-docker:
	$(COMPOSE) run --rm bench

report:
	$(PY) -m eval.report

demo:
	TRIPWIRE=off $(PY) -m agent.agent --attack do-01 --benign bw-03
	TRIPWIRE=on  $(PY) -m agent.agent --attack do-01 --benign bw-03

up:
	$(COMPOSE) up -d --build

down:
	$(COMPOSE) down

proxy:
	TRIPWIRE_BENCH_MODE=1 TRIPWIRE_ALLOW_BYPASS=1 $(PY) -m uvicorn tripwire.server:app --port 8080

attacker:
	$(PY) -m uvicorn attacks.server:app --port 8081

dashboard:
	$(PY) -m streamlit run dashboard/app.py

clean:
	rm -rf .pytest_cache .hypothesis results/*.db results/*.db-* **/__pycache__
