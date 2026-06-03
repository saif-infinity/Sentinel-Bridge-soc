# Sentinel Bridge - Advanced SOC Orchestration Dashboard

## 1. Project Overview
**Sentinel Bridge** is a high-performance, real-time Security Operations Center (SOC) orchestration platform. It is designed to act as a centralized "single pane of glass" by seamlessly integrating native network scanning capabilities with enterprise-grade security solutions like **Wazuh (SIEM)** and **Suricata (NIDS)**. 

The dashboard provides security analysts with immediate visibility into network topologies, active endpoint threats, hardware forensics, and network bandwidth anomalies through a premium, glassmorphism-styled UI.

---

## 2. System Architecture

The project is divided into a modern web frontend and a robust, asynchronous Python backend.

### 2.1. Frontend Architecture
- **Framework**: React (built with Vite for ultra-fast HMR).
- **Design System**: Premium Glassmorphism (custom CSS variables, translucent cards, micro-animations).
- **Data Visualization**: `recharts` for network bandwidth graphs and threat metrics.
- **Iconography**: `lucide-react` for clean, consistent UI components.
- **State Management**: React Hooks (`useState`, `useEffect`) handling real-time WebSocket streams and REST API polling.

### 2.2. Backend Architecture
- **Framework**: FastAPI (Asynchronous Python framework).
- **Database**: PostgreSQL (managed via SQLAlchemy ORM).
- **Core Services**:
  - `wazuh_service.py`: Interacts with Wazuh Manager API (Port 55000) and Wazuh Indexer (Port 9200).
  - `suricata.py`: Tails and parses `eve.json` for real-time network anomaly detection.
  - `broadcaster.py`: Manages WebSocket connections to push live data to the React frontend.
  - `scanner.py`: Handles continuous background network sweeps to discover unauthorized assets.

---

## 3. Key Features & Workflows

### 3.1. Smart Identity Resolution Engine
One of the most powerful features of Sentinel Bridge is its ability to bypass NAT/VPN obfuscation to identify the true source of a threat:
- **Syscollector Integration**: The backend queries the Wazuh Syscollector API to extract the *physical IP address*, *MAC address*, and *OS Username* of the machine.
- **Smart Fallback**: If the OS user scan is pending, the system dynamically falls back to the `agent.name` (typically the Windows Hostname/PC Name) to ensure the "Employee Name" field is never empty.
- **Alert Override**: Incoming alerts from Wazuh are intercepted, and their generic IPs are overwritten with the true, physical IP from the cache before being saved to the local database.

### 3.2. Real-Time Network Topology
- The dashboard dynamically generates a live map of the network.
- Groups agents by their Subnets.
- Visually indicates compromised nodes with pulsing red animations.

### 3.3. Forensic Investigation Modal
When an analyst clicks "Investigate" on an alert, a dynamic modal opens containing:
- **Network Identification**: Auto-sizing IPv6/IPv4 and MAC addresses.
- **Hardware Forensics**: Live CPU, RAM, and OS telemetry pulled from the Wazuh agent.
- **Installed Packages**: A verified list of software installed on the endpoint.

### 3.4. Global UI/UX Features
- **Bilingual Support**: Fully localized in English and French, persistent across sessions.
- **Audio Guard**: Built-in sound notifications for critical threat levels, which can be muted/unmuted globally.
- **Responsive Grid System**: Data density is maximized without visual clutter using a symmetric 2x2 grid layout.

---

## 4. API Endpoints

### Core Endpoints
- `GET /api/devices/` : Returns the live inventory of discovered assets.
- `GET /api/wazuh/alerts` : Returns the correlated security events mapped to local employees.
- `GET /api/wazuh/topology` : Returns the node/edge graph data for the topology view.
- `GET /api/wazuh/investigate/{agent_id}` : Aggregates deep forensic data (hardware, packages, netinfo) for the modal.

---

## 5. Deployment & Configuration

### Prerequisites
- Python 3.9+
- Node.js 18+
- PostgreSQL Server
- Active Wazuh Manager (with accessible API and Indexer)
- Active Suricata instance outputting to `eve.json`

### Environment Variables (.env)
*Note: Hardcoded keys in the development phase should be migrated to environment variables.*
- `DATABASE_URL`: PostgreSQL connection string.
- `WAZUH_API_URL`: URL of the Wazuh Manager API (usually `https://<ip>:55000`).
- `WAZUH_USER` / `WAZUH_PASS`: Wazuh API credentials.

### Running the Project
**Backend:**
```bash
cd backend
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

**Frontend:**
```bash
cd frontend
npm run dev
```

---

## 6. Future Roadmap
1. **Redis Caching**: Implement Redis for the `wazuh_service` cache to persist data across backend restarts.
2. **Automated Threat Response**: Implement Active Response triggers directly from the dashboard (e.g., "Isolate Host").
3. **AI Chatbot Integration**: Integrate an LLM (like Ollama) to automatically summarize complex alert chains into plain English.
