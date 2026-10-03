# NetBlock Fortress - developer / operator shortcuts
#   make test          offline engine + web test suite (no network needed)
#   make install       system install (uses sudo when needed)
#   make user-install  no-root install into ~/.adquit
#   make run           foreground run for hacking (dns :5353, web :8080)
#   make lint          python + shell syntax checks
#   make update        pull the newest fortress and refresh gravity
PY ?= python3
HERE := $(shell pwd)

.PHONY: help test lint run install user-install uninstall update gravity clean docker docker-run release verify-lists

help:
	@printf "NetBlock Fortress v19 targets:\n"
	@printf "  make test          run the offline test suite\n"
	@printf "  make lint          syntax-check python and shell\n"
	@printf "  make run           run the fortress in the foreground (dns 5353 / web 8080)\n"
	@printf "  make install       one-command system install (sudo)\n"
	@printf "  make user-install  rootless install into ~/.adquit\n"
	@printf "  make update        re-pull app.py + adquit from GitHub, then restart\n"
	@printf "  make gravity       re-download every enabled blocklist feed\n"
	@printf "  make docker        build the container image\n"
	@printf "  make clean         remove caches and local run state\n"

test:
	@ADQUIT_NO_PIP=1 $(PY) tests/run_tests.py
	@bash tests/test_cli.sh

# The shell list is a glob on purpose: the hand-written one kept missing files
# the day a second script landed in tests/, and a script nobody syntax-checks
# is a script nobody knows is broken.
SH = install.sh uninstall.sh bin/adquit $(wildcard tests/*.sh)

lint:
	@$(PY) -m py_compile app.py && echo "  python ok"
	@for f in $(SH); do bash -n $$f && echo "  shell ok: $$f"; done
	@command -v shellcheck >/dev/null 2>&1 && shellcheck -S warning $(SH) || echo "  (shellcheck not installed - skipped)"

run:
	@ADQUIT_HOME=$(HOME)/.adquit ADQUIT_NO_PIP=1 ADQUIT_DNS_PORT=5353 ADQUIT_WEB_PORT=8080 $(PY) app.py --serve

install:
	@bash install.sh

user-install:
	@ADQUIT_USER=1 bash install.sh

uninstall:
	@bash uninstall.sh

update:
	@command -v adquit >/dev/null 2>&1 && adquit update || bash install.sh

gravity:
	@$(PY) app.py --update-lists

verify-lists:
	@$(PY) app.py --verify-lists

docker:
	@docker build -t netblock-fortress:19 .

docker-run:
	@docker run -d --name adquit --network host -v adquit-data:/opt/adquit/data netblock-fortress:19 run

clean:
	@rm -rf __pycache__ .pytest_cache
	@printf "  cleaned\n"
