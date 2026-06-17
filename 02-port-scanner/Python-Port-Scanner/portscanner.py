"""
portscanner.py

Main entry point for the Python Port Scanner project.

This script :
- Parses command line arguments (IP, port(s), threads, rate, timeout, output file)
- Validates the inputs
- Calls the scanning function (scan_iterator)
- Outputs results to the console and to a JSON file

CLI-only mode : Interactive mode was removed because it introduced several untested edge cases when no CLI arguments were provided. The scanner now runs exclusively via the command-line interface.
"""

from typing import List
from functions.scan_iterator import scan_iterator
from functions.write_to_console import write_to_console
from functions.store_to_file import store_to_file
from functions.validate_input import validate_ip, validate_port, validate_port_range, validate_filename
import logging
import argparse

# -----------------------------
# Logging setup
# -----------------------------
logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    force=True,
)

# -----------------------------
# Core function
# -----------------------------
def portscanner(ip_address: str,
                ports: List[int],
                max_threads: int,
                max_connections_per_sec: float,
                output_file: str,
                timeout: float):
    """
    Runs the port scanner on a given IP and list of ports.

    Args:
        ip_address (str) : Target IPv4 address.
        ports (List[int]) : List of ports to scan.
        max_threads (int) : Maximum number of concurrent threads.
        max_connections_per_sec (float) : Maximum global connection attempts per second.
        output_file (str) : JSON filename to store results.
        timeout (float) : Socket timeout in seconds.

    Returns:
        None. Results are written to console and output file.
    """

    # Perform port scanning
    scan_result: List[tuple[int, bool]] = scan_iterator(
        ip_address, ports, max_threads, max_connections_per_sec, timeout
    )

    # Output results to console
    write_to_console(ip_address, scan_result)

    # Store results in JSON file
    store_to_file(ip_address, scan_result, output_file)


# -----------------------------
# Command line interface (CLI)
# -----------------------------
def main():
    """
    Parses CLI arguments and runs the portscanner.
    """

    # Argument parser
    parser = argparse.ArgumentParser(
        description="Python Port Scanner",
        epilog="Example: python3 portscanner.py -t 192.168.56.101 -p 20-100"
    )

    # Required arguments
    parser.add_argument(
        "-t", "--target", type=str, required=True,
        help="Target IP address (example: 192.168.1.10)"
    )
    parser.add_argument(
        "-p", "--ports", type=str, required=True,
        help="Port or range of ports (example: 80 or 20-100)"
    )

    # Optional arguments
    parser.add_argument(
        "-th", "--threads", type=int, default=100,
        help="Maximum number of threads (default = 100)"
    )
    parser.add_argument(
        "-r", "--rate", type=float, default=100.0,
        help="Maximum connections per second (default = 100.0)"
    )
    parser.add_argument(
        "-ti", "--timeout", type=float, default=1.0,
        help="Socket timeout in seconds (default = 1.0)"
    )
    parser.add_argument(
        "-o", "--output", default="scan_results.json",
        help="Output JSON file (default: scan_results.json)"
    )

    # Read arguments
    args = parser.parse_args()

    # Validate inputs
    try:
        ip_address = validate_ip(args.target)

        try:
            ports = validate_port_range(args.ports)
        except ValueError:
            ports = validate_port(args.ports)

        output_file = validate_filename(args.output)

    except ValueError as e:
        print(f"{e}")
        exit(1)

    # Run the scanner
    portscanner(
        ip_address=ip_address,
        ports=ports,
        max_threads=args.threads,
        max_connections_per_sec=args.rate,
        output_file=output_file,
        timeout=args.timeout
    )


# -----------------------------
# Entry point
# -----------------------------
if __name__ == "__main__":
    main()