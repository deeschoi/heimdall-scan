.PHONY: install bench-up bench-down bench-seed eval scan test lint clean

install:
	python3 -m venv .venv && . .venv/bin/activate && pip install -e ".[dev]"

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

test:
	pytest -q

clean:
	rm -rf .tmp *.sarif eval-*.json
