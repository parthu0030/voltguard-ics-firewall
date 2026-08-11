# VoltGuard – Physics-Aware ICS/SCADA Intrusion Detection System

<p align="center">
  <strong>⚡ VoltGuard IDS</strong><br/>
  A production-quality desktop IDS for Industrial Control Systems (ICS) and SCADA networks
</p>

---

## Overview

VoltGuard is an **offline-first, physics-aware** Intrusion Detection System designed to protect ICS/SCADA infrastructure. It combines deep packet inspection of industrial protocols (Modbus TCP, DNP3) with a physics simulation engine that models expected process behaviour. Deviations from either the network rule set or the physical model trigger security alerts.

---

## Architecture

```
VoltGuard/
├── app.py                  ← Application entry-point, MainWindow, stylesheet
├── ui/                     ← PySide6 view layer (MVC "View")
│   ├── dashboard.py        ← Live stat cards + recent-activity feed
│   ├── packet_monitor.py   ← Real-time packet capture table
│   ├── physics_monitor.py  ← Live gauges + rolling PyQtGraph charts
│   ├── analytics.py        ← Matplotlib protocol pie + action bar chart
│   ├── reports.py          ← Alert table with acknowledge / export (PDF, CSV)
│   └── settings.py         ← All configurable parameters
├── core/                   ← Business logic layer (MVC "Model + Controller")
│   ├── packet_capture.py   ← Thread-safe Scapy capture engine
│   ├── protocol_parser.py  ← Modbus TCP + DNP3 parser
│   ├── physics_engine.py   ← Process-variable simulation (pressure, flow, temp, RPM)
│   ├── decision_engine.py  ← Rule-chain allow/block/alert engine
│   └── logger.py           ← Structured multi-stream logging
├── database/
│   └── database.py         ← SQLite manager (packet_logs, alerts, scan_history, settings)
├── config/
│   └── config_manager.py   ← Typed settings facade over the DB
├── assets/                 ← Icons, images (future)
├── logs/                   ← Rotating log files
├── exports/                ← CSV / PDF report exports
└── tests/                  ← Unit tests (future)
```

---

## Tech Stack

| Component          | Library / Tool              |
|--------------------|-----------------------------|
| Desktop GUI        | PySide6 (Qt 6)              |
| Packet capture     | Scapy                       |
| Database           | SQLite 3 (built-in)         |
| Numerical/Physics  | NumPy, SciPy                |
| Live charts        | PyQtGraph                   |
| Analytics charts   | Matplotlib                  |
| Data manipulation  | Pandas                      |
| PDF reports        | ReportLab                   |
| Language           | Python 3.10+                |

---

## Features (Week 1)

- **Dark-themed professional dashboard** with animated live-capture indicator
- **Packet Monitor** — real-time table of captured packets with start/stop controls
- **Physics Monitor** — live gauge cards + scrolling PyQtGraph charts for pressure, flow, temperature, and RPM
- **Analytics** — Matplotlib protocol distribution pie + packet-action bar chart
- **Reports** — Security alert table with acknowledge workflow, CSV and PDF export
- **Settings** — Interface picker, logging level, physics thresholds — all persisted to SQLite
- **Protocol Parser** — Modbus TCP (port 502) and DNP3 (port 20000) with function-code lookup tables
- **Decision Engine** — Priority-ordered rule chain with built-in ICS security rules
- **Physics Engine** — Reusable simulation skeleton for pressure, flow, temperature, and RPM
- **Structured Logging** — Separate rotating log files: app, packets, security, errors

---

## Installation

### Prerequisites
- Python 3.10 or higher
- On macOS/Linux: run with `sudo` for raw packet capture privileges

### Setup

```bash
# 1. Clone the repository
git clone https://github.com/your-org/voltguard-ics-firewall.git
cd voltguard-ics-firewall

# 2. Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate          # macOS / Linux
# .venv\Scripts\activate           # Windows

# 3. Install dependencies
pip install -r requirements.txt
```

---

## Running

```bash
# Standard launch (no packet capture — for development)
python app.py

# With live packet capture (requires elevated privileges)
sudo python app.py
```

> **Note:** On macOS you may need to grant Terminal/your IDE "Full Disk Access" and run with `sudo` to capture packets on physical interfaces.

---

## Future Roadmap

### Week 2
- Full PID-based physics equations for pressure, flow, temperature, RPM
- Stuxnet-style attack simulation scenarios
- Physics-anomaly-to-alert integration

### Week 3
- Machine-learning anomaly detection (Isolation Forest / LSTM)
- Real-time alert notifications (desktop + email)
- Protocol plugin system for EtherNet/IP, OPC-UA

### Week 4
- Replay attack detection
- GIS-based network topology map
- REST API for integration with external SIEMs

### Week 5
- Full test suite (pytest + hypothesis)
- Docker packaging
- GitHub Actions CI/CD pipeline

---

## Security Notice

VoltGuard is a **monitoring and alerting** tool. It does not actively block network traffic at the OS level in Week 1 — decisions are logged and displayed in the UI. Active firewall enforcement via nftables/iptables is planned for Week 3.

---

## License

MIT License — see [LICENSE](LICENSE) for details.
