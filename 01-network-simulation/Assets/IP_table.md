# IP Addressing Table

> 🔴 Red = Default gateway of the VLAN  
> 🔵 Blue = Default gateway of the central switch (internet access)  
> Subnet mask `/27` = `255.255.255.224` | `/28` = `255.255.255.240`

---

## VLAN 10 — Management

| Device Type | Device Name | IP Address | Subnet Mask |
|-------------|-------------|------------|-------------|
| Virtual L3 Switch *(gateway)* | VS-1 | 192.168.1.1 | /27 |
| Switch | MG-SW-1 | 192.168.1.2 | /27 |
| Printer | MG-PR-1 | 192.168.1.3 | /27 |
| Workstation | MG-PC-1 | DHCP 192.168.1.4–28 | /27 |
| Workstation | MG-PC-2 | DHCP 192.168.1.4–28 | /27 |
| Workstation | MG-PC-3 | DHCP 192.168.1.4–28 | /27 |
| Workstation | MG-PC-4 | DHCP 192.168.1.4–28 | /27 |
| Workstation | MG-PC-5 | DHCP 192.168.1.4–28 | /27 |
| Layer 3 Switch *(core)* | VS-1-1 | 192.168.1.29 | /27 |
| Layer 3 Switch *(core)* | VS-1-2 | 192.168.1.30 | /27 |

---

## VLAN 20 — Production

| Device Type | Device Name | IP Address | Subnet Mask |
|-------------|-------------|------------|-------------|
| Virtual L3 Switch *(gateway)* | VS-1 | 192.168.1.33 | /27 |
| Switch | PD-SW-1 | 192.168.1.34 | /27 |
| Printer | PD-PR-1 | 192.168.1.35 | /27 |
| Workstation | PD-PC-1 | DHCP 192.168.1.36–60 | /27 |
| Workstation | PD-PC-2 | DHCP 192.168.1.36–60 | /27 |
| Workstation | PD-PC-3 | DHCP 192.168.1.36–60 | /27 |
| Workstation | PD-PC-4 | DHCP 192.168.1.36–60 | /27 |
| Workstation | PD-PC-5 | DHCP 192.168.1.36–60 | /27 |
| Workstation | PD-PC-6 | DHCP 192.168.1.36–60 | /27 |
| Workstation | PD-PC-7 | DHCP 192.168.1.36–60 | /27 |
| Workstation | PD-PC-8 | DHCP 192.168.1.36–60 | /27 |
| Workstation | PD-PC-9 | DHCP 192.168.1.36–60 | /27 |
| Workstation | PD-PC-10 | DHCP 192.168.1.36–60 | /27 |
| Layer 3 Switch *(core)* | VS-1-1 | 192.168.1.61 | /27 |
| Layer 3 Switch *(core)* | VS-1-2 | 192.168.1.62 | /27 |

---

## VLAN 30 — Support-1

| Device Type | Device Name | IP Address | Subnet Mask |
|-------------|-------------|------------|-------------|
| Virtual L3 Switch *(gateway)* | VS-1 | 192.168.1.65 | /27 |
| Switch | SP1-SW-1 | 192.168.1.66 | /27 |
| Printer | SP1-PR-1 | 192.168.1.67 | /27 |
| Workstation | SP1-PC-1 | DHCP 192.168.1.68–92 | /27 |
| Workstation | SP1-PC-2 | DHCP 192.168.1.68–92 | /27 |
| Workstation | SP1-PC-3 | DHCP 192.168.1.68–92 | /27 |
| Workstation | SP1-PC-4 | DHCP 192.168.1.68–92 | /27 |
| Workstation | SP1-PC-5 | DHCP 192.168.1.68–92 | /27 |
| Workstation | SP1-PC-6 | DHCP 192.168.1.68–92 | /27 |
| Workstation | SP1-PC-7 | DHCP 192.168.1.68–92 | /27 |
| Workstation | SP1-PC-8 | DHCP 192.168.1.68–92 | /27 |
| Workstation | SP1-PC-9 | DHCP 192.168.1.68–92 | /27 |
| Workstation | SP1-PC-10 | DHCP 192.168.1.68–92 | /27 |
| Layer 3 Switch *(core)* | VS-1-1 | 192.168.1.93 | /27 |
| Layer 3 Switch *(core)* | VS-1-2 | 192.168.1.94 | /27 |

---

## VLAN 40 — Support-2

| Device Type | Device Name | IP Address | Subnet Mask |
|-------------|-------------|------------|-------------|
| Virtual L3 Switch *(gateway)* | VS-1 | 192.168.1.97 | /27 |
| Switch | SP2-SW-1 | 192.168.1.98 | /27 |
| Printer | SP2-PR-1 | 192.168.1.99 | /27 |
| Workstation | SP2-PC-1 | DHCP 192.168.1.100–125 | /27 |
| Workstation | SP2-PC-2 | DHCP 192.168.1.100–125 | /27 |
| Workstation | SP2-PC-3 | DHCP 192.168.1.100–125 | /27 |
| Workstation | SP2-PC-4 | DHCP 192.168.1.100–125 | /27 |
| Workstation | SP2-PC-5 | DHCP 192.168.1.100–125 | /27 |
| Workstation | SP2-PC-6 | DHCP 192.168.1.100–125 | /27 |
| Workstation | SP2-PC-7 | DHCP 192.168.1.100–125 | /27 |
| Workstation | SP2-PC-8 | DHCP 192.168.1.100–125 | /27 |
| Workstation | SP2-PC-9 | DHCP 192.168.1.100–125 | /27 |
| Workstation | SP2-PC-10 | DHCP 192.168.1.100–125 | /27 |
| Layer 3 Switch *(core)* | VS-1-1 | 192.168.1.126 | /27 |
| Layer 3 Switch *(core)* | VS-1-2 | 192.168.1.127 | /27 |

---

## VLAN 50 — Study

| Device Type | Device Name | IP Address | Subnet Mask |
|-------------|-------------|------------|-------------|
| Virtual L3 Switch *(gateway)* | VS-1 | 192.168.1.129 | /27 |
| Switch | ST-SW-1 | 192.168.1.130 | /27 |
| Printer | ST-PR-1 | 192.168.1.131 | /27 |
| Workstation | ST-PC-1 | DHCP 192.168.1.132–156 | /27 |
| Workstation | ST-PC-2 | DHCP 192.168.1.132–156 | /27 |
| Workstation | ST-PC-3 | DHCP 192.168.1.132–156 | /27 |
| Workstation | ST-PC-4 | DHCP 192.168.1.132–156 | /27 |
| Workstation | ST-PC-5 | DHCP 192.168.1.132–156 | /27 |
| Workstation | ST-PC-6 | DHCP 192.168.1.132–156 | /27 |
| Workstation | ST-PC-7 | DHCP 192.168.1.132–156 | /27 |
| Workstation | ST-PC-8 | DHCP 192.168.1.132–156 | /27 |
| Layer 3 Switch *(core)* | VS-1-1 | 192.168.1.157 | /27 |
| Layer 3 Switch *(core)* | VS-1-2 | 192.168.1.158 | /27 |

---

## VLAN 60 — IT Department

| Device Type | Device Name | IP Address | Subnet Mask |
|-------------|-------------|------------|-------------|
| Virtual L3 Switch *(gateway)* | VS-1 | 192.168.1.161 | /27 |
| Switch | IT-SW-1 | 192.168.1.162 | /27 |
| Printer | IT-PR-1 | 192.168.1.163 | /27 |
| DHCP Server | IT-DHCP-1 | 192.168.1.164 | /27 |
| AAA Server | IT-AAA-1 | 192.168.1.165 | /27 |
| Workstation | IT-PC-1 | DHCP 192.168.1.166–189 | /27 |
| Workstation | IT-PC-2 | DHCP 192.168.1.166–189 | /27 |
| Workstation | IT-PC-3 | DHCP 192.168.1.166–189 | /27 |
| Workstation | IT-PC-4 | DHCP 192.168.1.166–189 | /27 |
| Workstation | IT-PC-5 | DHCP 192.168.1.166–189 | /27 |
| Layer 3 Switch *(core)* | VS-1-1 | 192.168.1.190 | /27 |
| Layer 3 Switch *(core)* | VS-1-2 | 192.168.1.191 | /27 |

---

## VLAN 70 — DMZ

| Device Type | Device Name | IP Address | Subnet Mask |
|-------------|-------------|------------|-------------|
| Virtual L3 Switch *(gateway)* | VS-1 | 192.168.1.197 | /28 |
| Switch | DMZ-SW-1 | 192.168.1.193 | /28 |
| Router | DMZ-RT-1 | 192.168.1.194 | /28 |
| DNS Server | DMZ-DNS-1 | 192.168.1.195 | /28 |
| Layer 3 Switch *(core)* | VS-1-1 | 192.168.1.198 | /28 |
| Layer 3 Switch *(core)* | VS-1-2 | 192.168.1.199 | /28 |

---

## VLAN 80 — Internal Servers

| Device Type | Device Name | IP Address | Subnet Mask |
|-------------|-------------|------------|-------------|
| Virtual L3 Switch *(gateway)* | VS-1 | 192.168.1.209 | /28 |
| Switch | IS-SW-1 | 192.168.1.210 | /28 |
| AAA Server | IS-AAA-1 | 192.168.1.211 | /28 |
| DHCP Server | IS-DHCP-1 | 192.168.1.212 | /28 |
| FTP Server | IS-FTP-1 | 192.168.1.213 | /28 |
| Layer 3 Switch *(core)* | VS-1-1 | 192.168.1.214 | /28 |
| Layer 3 Switch *(core)* | VS-1-2 | 192.168.1.215 | /28 |
