import asyncio
import json
from backend.app.services.wazuh_service import wazuh_service

async def test():
    try:
        topo = await wazuh_service.get_topology()
        json.dumps(topo)
        print('JSON OK')
    except Exception as e:
        print(f"JSON ERROR: {type(e).__name__}: {e}")

if __name__ == "__main__":
    asyncio.run(test())
