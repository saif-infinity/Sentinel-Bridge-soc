import asyncio


class Broadcaster:
    def __init__(self):
        self._clients = set()
        self._lock = asyncio.Lock()

    async def connect(self, ws):
        async with self._lock:
            self._clients.add(ws)

    async def disconnect(self, ws):
        async with self._lock:
            self._clients.discard(ws)

    async def broadcast(self, payload: dict):
        async with self._lock:
            for ws in list(self._clients):
                try:
                    await ws.send_json(payload)
                except Exception:
                    self._clients.discard(ws)

broadcaster = Broadcaster()
