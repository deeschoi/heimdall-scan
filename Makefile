.PHONY: install bench-up bench-down bench-seed eval scan test lint clean \
        vulnapp-up vulnapp-down eval-vulnapp scan-vulnapp ci

install:
	python3 -m venv .venv && . .venv/bin/activate && pip install -e ".[dev,vulnapp]"

# Bring up the local benchmark targets (VAmPI vuln + safe, Juice Shop).
bench-up:
	docker compose -f benchmarks/compose.yml up -d

bench-down:
	docker compose -f benchmarks/compose.yml down -v

# VAmPI starts with an empty DB; seed both instances.
bench-seed:
	curl -sf http://127.0.0.1:5001/createdb >/dev/null && echo "vuln seeded"
	curl -sf http://127.0.0.1:5002/createdb >/dev/null && echo "safe seeded"

# Score detection against frozen ground truth.
eval: bench-seed
	oedipus eval vampi

scan:
	oedipus scan --suite vampi --format md

# --- oedipus-vulnapp: the project's own target -------------------------------
# Build + run both the vulnerable (:8000) and hardened (:8001) builds via Docker.
vulnapp-up:
	docker compose -f benchmarks/compose.yml up -d --build vulnapp-vuln vulnapp-safe

vulnapp-down:
	docker compose -f benchmarks/compose.yml rm -sf vulnapp-vuln vulnapp-safe

# No Docker? Run both builds locally instead:
#   PORT=8000 VULNAPP_SAFE=0 python -m vulnapp &
#   PORT=8001 VULNAPP_SAFE=1 python -m vulnapp &
eval-vulnapp:
	oedipus eval vulnapp --min-recall 1.0 --max-fp 0

scan-vulnapp:
	oedipus scan --suite vulnapp --format md

test:
	pytest -q

# Same pytest invocation as .github/workflows/ci.yml (skips live VAmPI).
ci:
	pytest -q --ignore=tests/test_vampi_live.py

clean:
	rm -rf .tmp *.sarif eval-*.json
