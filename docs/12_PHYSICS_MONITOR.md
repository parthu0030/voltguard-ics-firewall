# Physics Monitor

VoltGuard simulates an in-memory water distribution process for training and
verification only. It never controls a host firewall, network interface, PLC,
or physical equipment.

Each configurable tick applies pump/valve commands, ramps RPM, derives
pressure and flow, evolves temperature gradually, and updates bounded tank
volume. All rates and limits are provided by `PhysicsConfig` from
`config.json` with safe defaults.

## Security flow

`PhysicsSafetyMonitor` evaluates high/low pressure, high flow, high
temperature, overspeed, pump-with-no-flow, low tank level, and implausible
pressure changes. Cooldown-deduplicated violations travel through the existing
event path:

`SystemState → PhysicsViolation → SecurityEvent → AlertManager → SQLite → Analytics`

Critical violations map to `BLOCK`; other violations map to `ALERT`. All
enforcement remains simulated.

## Training scenarios

While running, the Physics Monitor exposes safe one-tick in-memory scenarios:
pressure spike, pump overspeed, high temperature, pump-with-no-flow, and low
tank level. They exist to exercise detection, risk, alerts, and analytics.

```bash
python -m src.main
python -m pytest -q
```
