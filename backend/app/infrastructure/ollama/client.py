import logging
import re

import httpx
import redis

from ...config import settings

logger = logging.getLogger(__name__)


def _sanitize(text: str) -> str:
    """Supprime les références d'images Markdown et caractères non-textes."""
    text = re.sub(r'!\[.*?\]\(.*?\)', '', text)  # ![alt](url)
    text = re.sub(r'<img[^>]*>', '', text)        # <img ...>
    text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', text)  # caracteres de controle
    return text.strip()[:500]


def _call_ollama(prompt: str) -> str:
    """
    Envoie un prompt à Ollama sans lock bloquant.
    Utilise un lock Redis non-bloquant pour éviter la surcharge du modèle,
    mais sans bloquer les autres requêtes plus de 30s.
    """
    redis_client = redis.Redis.from_url(settings.REDIS_URL)
    lock = redis_client.lock("ollama_lock", timeout=300, blocking_timeout=30)

    try:
        lock.acquire(blocking=True)
    except Exception:
        pass  # on continue même sans lock

    try:
        timeout = httpx.Timeout(300.0, connect=15.0)
        with httpx.Client(timeout=timeout) as client:
            response = client.post(
                f"{settings.OLLAMA_URL}/api/generate",
                json={
                    "model": settings.OLLAMA_MODEL,
                    "prompt": prompt,
                    "stream": False,
                    "options": {
                        "num_predict": 512,
                        "temperature": 0.7,
                        "top_p": 0.9
                    }
                }
            )
            if response.status_code == 200:
                return response.json().get("response", "")
            else:
                raise RuntimeError(f"Ollama HTTP {response.status_code}")
    except httpx.ConnectError:
        raise RuntimeError("Ollama non accessible. Lancez : ollama serve")
    finally:
        try:
            lock.release()
        except Exception:
            pass
