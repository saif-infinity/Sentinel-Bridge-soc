PYTHON ?= python3
RUFF ?= ruff

.PHONY: help install test lint fmt demo validate clean

help:
	@echo "Cibles disponibles :"
	@echo "  install   installer le paquet en mode éditable avec les outils de dev"
	@echo "  test      lancer la suite pytest"
	@echo "  lint      vérifier le style avec ruff"
	@echo "  fmt       corriger automatiquement les imports et le style"
	@echo "  demo      afficher un échantillon de scénarios et l'inventaire"
	@echo "  validate  valider le scénario d'exemple"
	@echo "  clean     supprimer les caches de test et de build"

install:
	$(PYTHON) -m pip install -e ".[dev]"

test:
	$(PYTHON) -m pytest

lint:
	$(RUFF) check .

fmt:
	$(RUFF) check --fix .

demo:
	PYTHONPATH=src $(PYTHON) -m labtools.cli create -s auth-bruteforce -n 2
	@echo "---"
	PYTHONPATH=src $(PYTHON) -m labtools.cli catalog --category reseau

validate:
	PYTHONPATH=src $(PYTHON) -m labtools.cli validate examples/custom-scenario.json

clean:
	rm -rf .pytest_cache .ruff_cache build dist
	rm -rf src/*.egg-info *.egg-info
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
