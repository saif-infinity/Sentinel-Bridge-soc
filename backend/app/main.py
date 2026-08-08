"""Thin uvicorn entry point — deployment contract: `uvicorn app.main:app`.

The actual composition root is `app.interface.main`. This module is a
permanent shim so start.sh / start.bat / Makefile / docker-compose keep
working unchanged. There is intentionally no `if __name__ == "__main__"`
block: the original main.py never had one, and nothing invokes it.
"""
from .interface.main import app  # noqa: F401

__all__ = ["app"]
