# Python Port Scanner

A multithreaded **TCP port scanner written in Python** that scans ports on a target host with configurable concurrency and rate limiting.

The scanner validates inputs, scans ports concurrently, and outputs results both **to the console and to a JSON file**.

The main entry point is `portscanner.py`, which parses CLI arguments, validates inputs, performs the scan, and stores the results.

---

# Features

- Multithreaded port scanning
- Global rate limiting for connection attempts
- Input validation for:
  - IP addresses
  - Ports
  - Port ranges
  - Output filenames
- Clean console output with common service names
- JSON export of scan results
- Logging support

---

# Project Structure

```
Python-Port-Scanner
│
├── portscanner.py          # Main CLI entry point
│
├── functions
│   ├── scan_iterator.py    # Multithreaded scanning logic
│   ├── socket_connection.py# TCP connection to a port
│   ├── write_to_console.py # Console output formatting
│   ├── store_to_file.py    # Save results to JSON
│   ├── validate_input.py   # Input validation utilities
│   └── take_input.py       # Interactive input (optional/testing)
│
└── README.md
```

---

# Installation

Clone the repository:

```bash
git clone https://github.com/vaishnu-18/python-port-scanner.git
cd python-port-scanner
```

No external dependencies are required.

Recommended Python version:

```
Python 3.10+
```

---

# Usage

Run the scanner using the CLI.

### Basic scan

```bash
python portscanner.py -t 192.168.1.1 -p 80
```

### Scan a range of ports

```bash
python portscanner.py -t 192.168.1.1 -p 20-100
```

---

# CLI Arguments

| Argument | Description | Default |
|--------|--------|--------|
| `-t`, `--target` | Target IPv4 address | required |
| `-p`, `--ports` | Port or port range | required |
| `-th`, `--threads` | Maximum threads | 100 |
| `-r`, `--rate` | Max connections per second | 100 |
| `-ti`, `--timeout` | Socket timeout (seconds) | 1.0 |
| `-o`, `--output` | Output JSON file | scan_results.json |

Example:

```bash
python portscanner.py \
-t 192.168.1.1 \
-p 1-1024 \
-th 200 \
-r 300 \
-ti 0.5 \
-o results.json
```

---

# Example Output

Console output:

```
Scan Results
------------------------------------------------------------
IP              PORT      STATUS     COMMON PORT
------------------------------------------------------------
192.168.1.1     22        OPEN       SSH
192.168.1.1     80        OPEN       HTTP
192.168.1.1     443       CLOSED     HTTPS
```

JSON output:

```json
[
  {
    "ip": "192.168.1.1",
    "port": 22,
    "status": "OPEN"
  }
]
```

---

# Logging

Logging is enabled by default at the **INFO level**.

Example:

```
INFO - Starting port scan on 192.168.1.1 ports 20-100
INFO - Port scan finished in 0.52 seconds
```
---

# Limitations

- IPv4 only
- TCP connect scanning only
- Port state only shows OPEN/CLOSED and not FILTERED/TIMED-OUT
- File output only supports .json format

---

# Educational Purpose

This project demonstrates:

- socket programming
- concurrency with `ThreadPoolExecutor`
- rate limiting
- input validation
- modular project structure

---

# License

MIT License