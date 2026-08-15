# System Architecture

Industrial Device
        │
        ▼
Incoming Modbus TCP Packet
        │
        ▼
Packet Parser (Python)
        │
        ▼
Physics Engine (Python)
        │
        ▼
Decision Engine (Rust)
        │
        ▼
Allow / Block Packet
        │
        ▼
Dashboard (Qt C++)
        │
        ▼
SQLite Database
        │
        ▼
Analytics & Reports

---

Each module must remain independent.

Communication should happen through clean interfaces.

Business logic must never exist inside UI files.