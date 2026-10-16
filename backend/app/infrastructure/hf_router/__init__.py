"""HF Router client."""

# Explicit re-export (PEP 484): this package is a facade over .client, so the name
# is imported for other modules to use, not to be called here.
from app.infrastructure.hf_router.client import call_hf_router as call_hf_router

__all__ = ["call_hf_router"]
