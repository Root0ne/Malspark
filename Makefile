.PHONY: test lint typecheck format setup migrate doctor env-init check ci-check pre-commit-run prepare-attck prepare-api-db docker-build docker-up docker-down docker-logs dev-up dev-down dev-logs create-admin fe-rebuild worker-restart rebuild-ghidra external semgrep

test:
	uv run pytest tests/ -q

test-verbose:
	uv run pytest tests/ -v

test-qdrant:
	QDRANT_URL=http://localhost:6333 uv run pytest tests/unit/test_qdrant_store.py -v

test-unit:
	uv run pytest tests/unit/ -q

test-integration:
	uv run pytest tests/integration/ -q

# Everything Python in the repo, not just the library. `src/ tests/` left the
# FastAPI app, the arq worker, the MCP sidecars and scripts/ outside the gate:
# pre-commit still ran ruff over them because it works on staged files, so the
# only way to drift was to go a long time without being staged — which is
# exactly what services/network-mcp/server.py did, unformatted since 8e3370c and
# unnoticed because nothing ever looked at the whole tree.
PY_SOURCES = src/ tests/ apps/api/ services/ scripts/

lint:
	uv run ruff check $(PY_SOURCES)

format:
	uv run ruff check --fix $(PY_SOURCES)
	uv run ruff format $(PY_SOURCES)

format-check:
	uv run ruff format --check $(PY_SOURCES)

# apps/api/ included deliberately: the worker and the report service hold this
# branch's most consequential fixes and had never once been type-checked, in the
# Makefile or in pre-commit. It costs ~51 extra files and found one missing
# annotation.
typecheck:
	uv run mypy src/ apps/api/

# Same rulesets CI runs in the semgrep job, pinned to the same version, over
# the same targets — the frontend included: its files are application code and
# were covered by CodeQL alone.
semgrep:
	uv run --with semgrep==1.176.0 semgrep scan --config p/python --config p/security-audit --config p/typescript --config p/react --error --metrics=off src/ apps/api/ services/ scripts/ apps/web/src/

# Full local quality gate (mirrors CI)
check: lint format-check typecheck test

# Quick gate without typecheck (fast feedback loop)
ci-check: lint format-check test

# Setup and the stack's commands live in one standard-library script that runs
# the same on Windows, macOS and Linux; each target below is a one-line call to
# it. Without make (native Windows, say), run the script itself:
#
#   uv run --no-project python scripts/dev/malspark_dev.py setup
#   uv run --no-project python scripts/dev/malspark_dev.py env init
#   uv run --no-project python scripts/dev/malspark_dev.py up
#
# `doctor` says what this host has and lacks for the stack.
DEV = uv run --no-project python scripts/dev/malspark_dev.py

# The host environment a developer works in (uv sync, pre-commit), then what
# `external` fetches. A host that only runs the stack needs `external` alone.
setup:
	$(DEV) setup --dev

# Applies the API's Alembic migrations to the configured database. The API
# does not run them on startup unless RUN_MIGRATIONS_ON_STARTUP is set, so
# run this after every pull that adds a revision under apps/api/alembic/.
# DATABASE_URL comes from the process environment, with bootstrap.env read
# over it when it is there.
migrate:
	$(DEV) migrate

# The third-party trees, at the refs this project was built and measured
# against, the Sigma rules and capa's data. external/ is not in version
# control: none of it is ours to redistribute. ik_llama.cpp, the commit the
# paper pins, only when named: `$(DEV) external ik_llama.cpp`.
external:
	$(DEV) external

doctor:
	$(DEV) doctor

env-init:
	$(DEV) env init

pre-commit-run:
	uv run pre-commit run --all-files

prepare-attck:
	uv run python scripts/knowledge/prepare_attck_malware_fixtures.py

# Regenerate the Windows API behaviour map and the API->ATT&CK map. The curated
# lists live in the script, not the JSON — the JSON is the artifact. Validates
# every technique ID against data/attck_valid_ids.json and refuses to write on
# any mismatch, so a typo fails loudly here rather than silently never firing.
prepare-api-db:
	uv run python scripts/knowledge/build_api_capability_db.py

# ── Docker Orchestration ───────────────────────────────────────────

# The backend containers run as MALSPARK_UID:MALSPARK_GID. A target that starts
# the stack sets both, unless the environment or docker/.env already does, to
# the invoking user's ids (the user behind sudo, not root), so data/samples and
# data/uploads stay that user's and volume-init does not refuse them as someone
# else's. A value in docker/.env is read without its quotes, spaces or inline
# comment; an id that still comes out 0 falls back to the image's 10001. A host
# without user ids (Windows) sets neither.
#
# The shipped compose file bind-mounts ./data over the image's /app/data, so the
# stack reads this checkout's rule corpora: docker-up names each one `external`
# has not fetched. The docker-* targets pass compose no -f, so they do read
# docker/docker-compose.override.yml. A down also stops the optional services
# (ghidra, qdrant) whatever COMPOSE_PROFILES says now.
docker-build:
	$(DEV) docker-build

docker-up:
	$(DEV) docker-up

docker-down:
	$(DEV) docker-down

docker-logs:
	$(DEV) docker-logs

# ── Development loop ───────────────────────────────────────────────
# The production stack bakes the frontend into an image and runs the worker
# under plain `arq`, so NEITHER picks up a source edit on its own. That cost
# real debugging time (a live analysis ran the previous worker build; the
# deployed UI was a stale bundle for a whole session), so the two ways out are
# spelled out here rather than left to be rediscovered.

# Live source for both: `next dev` for the frontend, watchfiles-supervised arq
# for the worker. Use this while developing.
#
# The bootstrap secrets (JWT_SECRET_KEY, SETTINGS_ENCRYPTION_KEY) still come
# from docker/.env for compose variable substitution; bootstrap.env (repo
# root, gitignored) is read over the environment here too, so the same file
# also covers `make migrate` and any bare host process you run outside Docker.
#
# COMPOSE_FILE_EXTRA adds compose files of your own after the shipped file and
# the overlays, each as one more `-f`, so it wins over all of them: a port
# moved, a volume added, a service turned off on this host. Several are
# separated by white space, and on Windows by `;`, so a path there may hold a
# space:
#
#   COMPOSE_FILE_EXTRA=docker/local.yml make dev-up
#   make dev-up COMPOSE_FILE_EXTRA="docker/local.yml docker/gpu.yml"
#
# Give the same value to dev-down and dev-logs. Elsewhere a path with a space
# in it is not supported: the value is split on white space. A path on the
# command line is read from the repository root; paths inside the file are
# read from docker/, the first file's directory. Compose reads
# docker-compose.override.yml on its own only when it is given no -f, and
# these targets give it at least two, so an override file is read here only
# when it is named in COMPOSE_FILE_EXTRA.
dev-up:
	$(DEV) up

dev-down:
	$(DEV) down

dev-logs:
	$(DEV) logs

# The first admin account, or an existing account promoted, in the running
# stack's API container (`malspark create-admin`, which reads the API's own
# DATABASE_URL there). The password is asked for on the terminal, never taken
# from the command line. Either stack: exec reaches the service by the compose
# project's name, whichever files started it.
#
# EMAIL is taken as written: `$(value ...)` keeps make from expanding a `$(...)`
# in it, the single quotes (each one inside written as '\'') keep the shell from
# reading it, and `--` keeps an address that starts with `-` an argument; the
# script hands it on as one argument. It is unexported, since make expands an
# exported variable to put it in a recipe's environment. It is read from the
# make command line only: an EMAIL exported in the shell (git and Debian's
# tools read one) is someone's own address, not the account meant here.
unexport EMAIL
QUOTED_EMAIL = '$(subst ','\'',$(value EMAIL))'

create-admin:
ifneq ($(origin EMAIL),command line)
	@echo "usage: make create-admin EMAIL=you@example.com (on the make command line; an EMAIL in the environment is not read)" >&2; exit 2
else
	@[ -n $(QUOTED_EMAIL) ] || { echo "usage: make create-admin EMAIL=you@example.com" >&2; exit 2; }
	$(DEV) create-admin -- $(QUOTED_EMAIL)
endif

# On the production stack, these are the two commands that make an edit real.
fe-rebuild:
	$(DEV) fe-rebuild

worker-restart:
	$(DEV) worker-restart

# ── Ghidra MCP Manager ─────────────────────────────────────────────

ghidra-status:
	uv run python scripts/dev/ghidra_manager.py status

ghidra-sync:
	uv run python scripts/dev/ghidra_manager.py sync

ghidra-build:
	uv run python scripts/dev/ghidra_manager.py build

ghidra-watch:
	uv run python scripts/dev/ghidra_manager.py watch

# Legacy alias
rebuild-ghidra: ghidra-build
