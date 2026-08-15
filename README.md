# VoltGuard — Physics-Aware ICS/SCADA Intrusion Detection System

<p align="center">
  <strong>⚡ VoltGuard IDS v1.0.0</strong><br/>
  A production-quality, offline-first desktop IDS for Industrial Control Systems (ICS) and SCADA networks
</p>

---

## Overview

VoltGuard is an **offline-first, physics-aware** Intrusion Detection System designed to protect ICS/SCADA infrastructure. It combines deep packet inspection of industrial protocols (Modbus TCP, DNP3) with a physics simulation engine that models expected process behaviour. Deviations from either the network rule set or the physical model trigger security alerts.

---

## Architecture

```
Industrial Device
        │
        ▼
Incoming Modbus TCP / DNP3 Packet
        │
        ▼
Packet Parser (Python)      ←  src/parser/         [BaseParser interface]
        │
        ▼
Physics Engine (Python)     ←  src/physics/        [BasePhysicsEngine interface]
        │
        ▼
Decision Engine (Python)    ←  src/decision_engine/ [BaseDecisionEngine interface]
        │
        ▼
Allow / Block Packet
        │
        ▼
Dashboard (PyQt6)           ←  src/ui/
        │
        ▼
SQLite Database             ←  voltguard.db
        │
        ▼
Analytics & Reports         ←  reports/
```

---

## Project Structure

```
voltguard-ics-firewall/
│
├── src/                         ← Application source
│   ├── main.py                  ← PyQt6 entry point & bootstrap
│   ├── constants.py             ← All project-wide constants
│   ├── exceptions.py            ← Custom exception hierarchy
│   ├── config.py                ← JSON + .env configuration loader
│   ├── logger.py                ← Rotating file logger factory
│   ├── utils.py                 ← Utility helper functions
│   ├── healthcheck.py           ← Pre-launch system health checks
│   ├── startup.py               ← Startup banner & sequence
│   │
│   ├── core/
│   │   └── app_state.py         ← Thread-safe runtime state singleton
│   │
│   ├── models/
│   │   └── app_models.py        ← Typed data classes (PacketLog, Alert, …)
│   │
│   ├── services/
│   │   ├── config_service.py    ← DB-backed settings manager
│   │   ├── database_service.py  ← SQLite CRUD service
│   │   ├── logging_service.py   ← Qt-aware logging service
│   │   └── theme_service.py     ← Dark/light theme management
│   │
│   ├── database/
│   │   └── db_manager.py        ← SQLite schema & migrations
│   │
│   ├── interfaces/              ← Abstract Base Classes (contracts)
│   │   ├── base_parser.py       ← BaseParser + ParsedPacket DTO
│   │   ├── base_physics.py      ← BasePhysicsEngine + PhysicsState DTO
│   │   └── base_engine.py       ← BaseDecisionEngine + FirewallRule + DecisionResult DTOs
│   │
│   ├── parser/                  ← Protocol parsers (Week 1 Day 2+)
│   ├── physics/                 ← Physics engines (Week 1 Day 2+)
│   ├── decision_engine/         ← Firewall logic (Week 3)
│   ├── dashboard/               ← Business logic backing UI (Week 2)
│   │
│   └── ui/
│       ├── main_window.py       ← Main window & sidebar navigation
│       └── pages/
│           ├── dashboard_page.py
│           ├── packet_monitor_page.py
│           ├── physics_monitor_page.py
│           ├── analytics_page.py
│           ├── reports_page.py
│           └── settings_page.py
│
├── tests/
│   └── test_day1.py             ← 107 unit tests (all passing)
│
├── docs/                        ← Project documentation
├── logs/                        ← Runtime log files (auto-generated)
├── reports/                     ← Generated PDF/CSV reports
├── assets/                      ← Icons and images
├── config.json                  ← Application configuration (auto-generated)
├── requirements.txt             ← Python dependencies
└── .gitignore
```

---

## Tech Stack

| Component | Library / Tool |
|-----------|---------------|
| Desktop GUI | PyQt6 (Qt 6) |
| Configuration | python-dotenv + JSON |
| Database | SQLite 3 (built-in) |
| Numerical / Physics | NumPy, SciPy (Week 2) |
| Packet Capture | Scapy (Week 1 Day 2) |
| Testing | pytest |
| Language | Python 3.10+ |

---

## Day 1 — Completed

The following foundational components are fully implemented and tested:

| Component | File | Status |
|-----------|------|--------|
| Constants | `src/constants.py` | ✅ Complete |
| Custom Exceptions | `src/exceptions.py` | ✅ Complete |
| Config Loader | `src/config.py` | ✅ Complete |
| Rotating Logger | `src/logger.py` | ✅ Complete |
| Utility Helpers | `src/utils.py` | ✅ Complete |
| Health Checker | `src/healthcheck.py` | ✅ Complete |
| Startup Sequence | `src/startup.py` | ✅ Complete |
| Base Interfaces | `src/interfaces/` | ✅ Complete |
| Sub-package Stubs | `src/parser/`, `src/physics/`, `src/decision_engine/`, `src/dashboard/` | ✅ Complete |
| Application State | `src/core/app_state.py` | ✅ Complete |
| Data Models | `src/models/app_models.py` | ✅ Complete |
| Services Layer | `src/services/` | ✅ Complete |
| Database Manager | `src/database/db_manager.py` | ✅ Complete |
| UI Pages (6) | `src/ui/pages/` | ✅ Complete |
| Unit Tests | `tests/test_day1.py` | ✅ 107 / 107 passed |

---

## Installation

### Prerequisites
- Python 3.10 or higher
- macOS / Linux (primary targets)

### Setup

```bash
# 1. Clone the repository
git clone https://github.com/parthu0030/voltguard-ics-firewall.git
cd voltguard-ics-firewall

# 2. Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate        # macOS / Linux
# .venv\Scripts\activate         # Windows

# 3. Install dependencies
pip install -r requirements.txt
```

---

## Running

```bash
# Launch the full PyQt6 desktop application
python3 -m src.main

# Or run the headless startup sequence (no GUI — useful for CI)
python3 -c "from src.startup import run_startup_sequence; run_startup_sequence()"

# Run the system health check
python3 -c "from src.healthcheck import HealthChecker; hc = HealthChecker(); hc.print_report()"

# Run all unit tests
python3 -m pytest tests/test_day1.py -v
```

> **Note:** On macOS you may need to grant Terminal / your IDE "Full Disk Access"
> and run with `sudo` to capture packets on physical interfaces (Week 1 Day 2+).

---

## Configuration

`config.json` is auto-generated on first run with safe defaults:

```json
{
  "app_version": "1.0.0",
  "log_level": "INFO",
  "selected_interface": "lo0",
  "theme": "dark",
  "db_path": "voltguard.db",
  "physics": {
    "pressure_max_bar": 10.0,
    "flow_max_lps": 50.0,
    "temp_max_celsius": 150.0,
    "rpm_max": 3600.0
  }
}
```

Environment variables with the `VOLTGUARD_` prefix override config values:
```bash
VOLTGUARD_LOG_LEVEL=DEBUG python3 -m src.main
```

---

## Exception Hierarchy

```
VoltGuardError (base)
├── ConfigurationError
├── ParserError
│   └── UnsupportedProtocolError
├── PhysicsError
│   └── SafetyConstraintViolation
├── DecisionEngineError
│   └── RuleViolationError
├── DashboardError
└── HealthCheckError
```

---

## Week 1 Roadmap

- **Day 1** ✅ Application foundation (this milestone)
- **Day 2** Modbus TCP packet generator + parser
- **Day 3** Basic physics engine (pressure, flow, temperature)
- **Day 4** Rule-based decision engine
- **Day 5** Integration + end-to-end pipeline test

---

## Future Roadmap

### Week 2
- Full PID-based physics equations
- Stuxnet-style attack simulation scenarios
- Dashboard integration with live physics data
- SQLite analytics and reporting

### Week 3
- Rust decision engine integration
- Machine-learning anomaly detection
- Active packet blocking (nftables/iptables)

### Week 4
- Full test suite + hypothesis-based property tests
- Docker packaging
- GitHub Actions CI/CD pipeline

---

## Security Notice

VoltGuard is a **monitoring and alerting** tool. Active packet blocking at the OS level is planned for Week 3.

---

## License

MIT License — see [LICENSE](LICENSE) for details.
