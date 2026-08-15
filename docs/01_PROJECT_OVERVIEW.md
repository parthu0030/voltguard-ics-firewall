# VoltGuard – Physics-Aware ICS/SCADA Intrusion Prevention System

## Project Overview

VoltGuard is a desktop-based Intrusion Prevention System (IPS) designed specifically for Industrial Control Systems (ICS) and SCADA environments.

Unlike traditional firewalls that inspect packet signatures, VoltGuard validates every incoming industrial command against a real-time physics simulation before allowing it to reach the industrial process.

The system predicts whether executing a command would violate safe operating conditions such as pressure, flow rate, temperature, or valve limits.

If the predicted physical state is unsafe, VoltGuard blocks the command immediately.

---

## Objectives

- Detect malicious industrial commands
- Validate commands using physics simulation
- Prevent unsafe operations
- Visualize system state
- Generate detailed logs
- Support offline industrial environments

---

## Target Users

- Industrial Engineers
- Security Analysts
- Researchers
- SCADA Operators

---

## Expected Output

A standalone desktop application capable of inspecting industrial traffic, simulating physical processes, making security decisions, and displaying results through an interactive dashboard.
