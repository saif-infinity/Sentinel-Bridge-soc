"""Client pour le routeur HF compatible OpenAI via httpx."""
import logging

import httpx

logger = logging.getLogger(__name__)


def call_hf_router(
    prompt: str,
    *,
    model: str,
    base_url: str,
    token: str,
    system: str | None = None,
    timeout: float = 120.0,
) -> str | None:
    """Appelle le routeur HF et retourne le contenu de la réponse.

    Retourne None en cas d'erreur, timeout, ou token vide.
    Ne journalise JAMAIS le token ni le contenu complet de la requête.
    """
    if not token:
        return None

    messages: list[dict] = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})

    payload = {
        "model": model,
        "messages": messages,
        "temperature": 0.3,
        "max_tokens": 1024,
    }

    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.post(
                f"{base_url.rstrip('/')}/chat/completions",
                headers={"Authorization": f"Bearer {token}"},
                json=payload,
            )
        if resp.status_code != 200:
            logger.error("HF router returned status %s", resp.status_code)
            return None
        data = resp.json()
        content = data.get("choices", [{}])[0].get("message", {}).get("content")
        return content
    except Exception as e:
        logger.error("HF router call failed: %s", e)
        return None
