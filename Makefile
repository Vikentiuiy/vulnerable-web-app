# vuln-sast-benchmark — per-target build/run/exploit/scan gates.
# Usage: make <goal> TARGET=java-web [PROFILE=default]
TARGET  ?= java-web
PROFILE ?= default
T        = targets/$(TARGET)
NAME     = $(TARGET)

.PHONY: help build up down exploit reference scan ablation test list

help:
	@echo "Goals: build up down exploit reference scan ablation test list"
	@echo "  make test TARGET=java-web        # build + run + exploit gate"
	@echo "  make scan TARGET=java-web PROFILE=default   # needs PTAI_TOKEN"
	@echo "  make ablation TARGET=java-web    # default->pm->config->max + deltas"

list:
	@ls -1 targets

build:
	cd $(T) && docker compose build

up:
	cd $(T) && docker compose up -d --build

down:
	cd $(T) && docker compose down -v

exploit:
	cd $(T) && python3 exploits/exploit_all.py

reference:
	python3 checker/build_reference.py --root $(T) -o $(T)/reference.sarif

# Full gate: the target must build, run, and be fully exploitable.
test: up
	@sleep 12
	cd $(T) && python3 exploits/exploit_all.py

scan:
	ptai/scan.sh $(T) $(PROFILE) results/$(NAME)-$(PROFILE).sarif
	python3 checker/sast_checker.py -r $(T)/reference.sarif -a results/$(NAME)-$(PROFILE).sarif

ablation:
	ptai/run_ablation.sh $(T)
