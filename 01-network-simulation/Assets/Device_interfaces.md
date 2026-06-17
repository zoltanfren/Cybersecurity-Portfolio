# Device Interface Configuration

---

## Access Switches

### MG-SW-1 — Management (VLAN 10)

| Interface | VLAN | Configuration |
|-----------|------|---------------|
| FastEthernet 0/1 | 10 | Trunk to central switch VS-1-1 |
| FastEthernet 0/2 | 10 | Trunk to central switch VS-1-2 |
| FastEthernet 0/3–8 | 10 | Access ports |
| FastEthernet 0/9–24 | 10 | Shut down |
| GigabitEthernet 0/1–2 | 10 | Shut down |

### PD-SW-1 — Production (VLAN 20)

| Interface | VLAN | Configuration |
|-----------|------|---------------|
| FastEthernet 0/1 | 20 | Trunk to central switch VS-1-1 |
| FastEthernet 0/2 | 20 | Trunk to central switch VS-1-2 |
| FastEthernet 0/3–13 | 20 | Access ports |
| FastEthernet 0/14–24 | 20 | Shut down |
| GigabitEthernet 0/1–2 | 20 | Shut down |

### SP1-SW-1 — Support-1 (VLAN 30)

| Interface | VLAN | Configuration |
|-----------|------|---------------|
| FastEthernet 0/1 | 30 | Trunk to central switch VS-1-1 |
| FastEthernet 0/2 | 30 | Trunk to central switch VS-1-2 |
| FastEthernet 0/3–13 | 30 | Access ports |
| FastEthernet 0/14–24 | 30 | Shut down |
| GigabitEthernet 0/1–2 | 30 | Shut down |

### SP2-SW-1 — Support-2 (VLAN 40)

| Interface | VLAN | Configuration |
|-----------|------|---------------|
| FastEthernet 0/1 | 40 | Trunk to central switch VS-1-1 |
| FastEthernet 0/2 | 40 | Trunk to central switch VS-1-2 |
| FastEthernet 0/3–13 | 40 | Access ports |
| FastEthernet 0/14–24 | 40 | Shut down |
| GigabitEthernet 0/1–2 | 40 | Shut down |

### ST-SW-1 — Study (VLAN 50)

| Interface | VLAN | Configuration |
|-----------|------|---------------|
| FastEthernet 0/1 | 50 | Trunk to central switch VS-1-1 |
| FastEthernet 0/2 | 50 | Trunk to central switch VS-1-2 |
| FastEthernet 0/3–11 | 50 | Access ports |
| FastEthernet 0/12–24 | 50 | Shut down |
| GigabitEthernet 0/1–2 | 50 | Shut down |

### IT-SW-1 — IT Department (VLAN 60)

| Interface | VLAN | Configuration |
|-----------|------|---------------|
| FastEthernet 0/1 | 60 | Trunk to central switch VS-1-1 |
| FastEthernet 0/2 | 60 | Trunk to central switch VS-1-2 |
| FastEthernet 0/3–10 | 60 | Access ports |
| FastEthernet 0/11–24 | 60 | Shut down |
| GigabitEthernet 0/1–2 | 60 | Shut down |

### DMZ-SW-1 — DMZ (VLAN 70)

| Interface | VLAN | Configuration |
|-----------|------|---------------|
| GigabitEthernet 0/1 | 70 | Trunk to central switch VS-1-1 |
| GigabitEthernet 1/1 | 70 | Trunk to central switch VS-1-2 |
| GigabitEthernet 2/1 | 70 | Access port (to DMZ-RT-1) |
| FastEthernet 3/1 | 70 | Access port (to DMZ-DNS-1) |
| FastEthernet 4/1–9/1 | 70 | Shut down |

### IS-SW-1 — Internal Servers (VLAN 80)

| Interface | VLAN | Configuration |
|-----------|------|---------------|
| FastEthernet 0/1 | 80 | Trunk to central switch VS-1-1 |
| FastEthernet 0/2 | 80 | Trunk to central switch VS-1-2 |
| FastEthernet 0/3–5 | 80 | Access ports |
| FastEthernet 0/6–24 | 80 | Shut down |
| GigabitEthernet 0/1–2 | 80 | Shut down |

---

## Core Switches

### VS-1-1 — Central Switch (Primary)

| Interface | VLAN | Configuration |
|-----------|------|---------------|
| FastEthernet 0/1 | 10 | Trunk to MG-SW-1 |
| FastEthernet 0/2 | 20 | Trunk to PD-SW-1 |
| FastEthernet 0/3 | 30 | Trunk to SP1-SW-1 |
| FastEthernet 0/4 | 40 | Trunk to SP2-SW-1 |
| FastEthernet 0/5 | 50 | Trunk to ST-SW-1 |
| FastEthernet 0/6 | 60 | Trunk to IT-SW-1 |
| GigabitEthernet 0/2 | 70 | Trunk to DMZ-SW-1 |
| FastEthernet 0/8 | 80 | Trunk to IS-SW-1 |
| GigabitEthernet 0/1 | 10–80 | Trunk to redundant switch VS-1-2 |

### VS-1-2 — Central Switch (Redundant)

| Interface | VLAN | Configuration |
|-----------|------|---------------|
| FastEthernet 0/1 | 10 | Trunk to MG-SW-1 |
| FastEthernet 0/2 | 20 | Trunk to PD-SW-1 |
| FastEthernet 0/3 | 30 | Trunk to SP1-SW-1 |
| FastEthernet 0/4 | 40 | Trunk to SP2-SW-1 |
| FastEthernet 0/5 | 50 | Trunk to ST-SW-1 |
| FastEthernet 0/6 | 60 | Trunk to IT-SW-1 |
| GigabitEthernet 0/2 | 70 | Trunk to DMZ-SW-1 |
| FastEthernet 0/8 | 80 | Trunk to IS-SW-1 |
| GigabitEthernet 0/1 | 10–80 | Trunk to redundant switch VS-1-1 |

---

## Border Router

### DMZ-RT1 — Border Router

| Interface | VLAN | Configuration |
|-----------|------|---------------|
| GigabitEthernet 0/0 | 70 | Access port (to DMZ-SW-1) |
| Serial 0/3/0 | — | Connection to ISP |
