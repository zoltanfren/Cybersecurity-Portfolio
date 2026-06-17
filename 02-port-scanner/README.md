# Project 2 — Python Port Scanner

> **Multithreaded TCP port scanner built in Python**  
> Team challenge | Duration: 7 days | Python 3.10+

---

## Overview

A CLI-based TCP port scanner written from scratch in Python. The scanner supports multithreaded scanning with configurable concurrency and rate limiting, validates all user inputs, and outputs results both to the console and to a JSON file.

The project was designed with a modular architecture — each concern (connection, scanning, validation, output) lives in its own module — and is accompanied by a design report, an ethics/detection report, and a full testing report.

---

## Repository Contents

```
02-python-port-scanner/
├── portscanner.py                      # Main CLI entry point
├── scan_results.json                   # Example scan output
├── Functions/
│   ├── scan_iterator.py                # Multithreaded scan loop + rate limiter
│   ├── socket_connection.py            # TCP connection handler
│   ├── validate_input.py               # Input validation (IP, ports, filename)
│   ├── write_to_console.py             # Formatted console output
│   └── store_to_file.py                # JSON file export
└── Reports/
    ├── Design_Report_Final.pdf         # Architecture and design decisions
    ├── Ethics_Detection_Report.pdf     # Ethical use and detection considerations
    └── Testing_Report.pdf              # Test cases and results
```

---

## Features

- **Multithreaded scanning** via `ThreadPoolExecutor` — configurable thread count
- **Thread-safe rate limiting** — global cap on connection attempts per second using a `Lock`-based `RateLimiter` class
- **Input validation** for IPv4 addresses, single ports, port ranges (0–65535), and output filenames
- **Service identification** — 80+ common ports mapped to their service names (SSH, HTTP, RDP, MySQL, etc.)
- **Dual output** — formatted console table and structured JSON file
- **Logging** at INFO level for scan start, finish, and elapsed time; DEBUG level for individual port results

---

## Architecture

The scanner is split into focused modules:

| Module | Responsibility |
|--------|---------------|
| `portscanner.py` | CLI argument parsing, input validation, orchestration |
| `scan_iterator.py` | Thread pool management, rate limiter, scan loop |
| `socket_connection.py` | Raw TCP connection attempt per port |
| `validate_input.py` | IP, port, port range, and filename validation |
| `write_to_console.py` | Console table formatting with service name lookup |
| `store_to_file.py` | JSON serialization of scan results |

The rate limiter (`RateLimiter` class in `scan_iterator.py`) uses `time.monotonic()` and a `threading.Lock` to enforce a global connection rate across all threads, preventing network flooding regardless of thread count.

---

## Usage

No external dependencies required — standard library only.

**Single port:**
```bash
python portscanner.py -t 192.168.1.1 -p 80
```

**Port range:**
```bash
python portscanner.py -t 192.168.1.1 -p 20-100
```

**Full options:**
```bash
python portscanner.py -t 192.168.1.1 -p 1-1024 -th 200 -r 300 -ti 0.5 -o results.json
```

### CLI Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `-t`, `--target` | Target IPv4 address | required |
| `-p`, `--ports` | Port or port range (e.g. `80` or `20-100`) | required |
| `-th`, `--threads` | Maximum concurrent threads | 100 |
| `-r`, `--rate` | Max connection attempts per second | 100.0 |
| `-ti`, `--timeout` | Socket timeout in seconds | 1.0 |
| `-o`, `--output` | Output JSON filename | scan_results.json |

---

## Example Output

**Console:**
```
Scan Results
------------------------------------------------------------
IP              PORT      STATUS    COMMON PORT
------------------------------------------------------------
192.168.1.1     22        OPEN      SSH
192.168.1.1     80        OPEN      HTTP
192.168.1.1     443       CLOSED    HTTPS
```

**JSON (`scan_results.json`):**
```json
[
  { "ip": "192.168.1.1", "port": 22, "status": "OPEN" },
  { "ip": "192.168.1.1", "port": 80, "status": "OPEN" },
  { "ip": "192.168.1.1", "port": 443, "status": "CLOSED" }
]
```

---

## Limitations

- IPv4 only
- TCP connect scan only (no SYN/UDP scanning)
- Port state is OPEN or CLOSED only — no FILTERED or TIMED-OUT distinction
- Output format is JSON only

---

## Legal & Ethical Use

This tool is intended for scanning systems you own or have explicit permission to test. Unauthorized port scanning may be illegal depending on your jurisdiction. See `Reports/Ethics_Detection_Report.pdf` for a full discussion of ethical considerations and detection risk.

---

## Skills Demonstrated

- Python socket programming
- Multithreading with `concurrent.futures.ThreadPoolExecutor`
- Thread-safe rate limiting with `threading.Lock`
- Input validation and error handling
- Modular project structure
- CLI design with `argparse`
- Structured JSON output
