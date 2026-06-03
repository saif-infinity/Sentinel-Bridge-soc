import asyncio
import httpx
from backend.app.services.wazuh_service import wazuh_service

async def test():
    try:
        print("Testing Wazuh topology generation...")
        topo = await wazuh_service.get_topology()
        print(f"Success! Found {len(topo['nodes'])} nodes and {len(topo['edges'])} edges.")
    except Exception as e:
        print(f"FAILED: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(test())
