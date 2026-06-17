"""
validate_input.py

Contains functions to validate IP addresses, ports, port ranges, and output filenames.

This module ensures :
- IP addresses are valid IPv4
- Ports are numeric and within 0-65535
- Output filenames are valid JSON files with allowed characters
"""

from typing import List
import re

# -----------------------------
# Port validation
# -----------------------------
def validate_port(input_port: str) -> List[int]:
    """
    Validate a single port input.

    Args:
        input_port (str): Port as a string (e.g., '80').

    Returns:
        List[int]: List containing a single valid port number.

    Raises:
        ValueError: If the port is invalid.
    """
    input_port = input_port.strip()

    if input_port == "":
        raise ValueError("PORT ERROR : Port number is empty !")

    try:
        port = int(input_port)
    except ValueError:
        if " " in input_port:
            raise ValueError("PORT ERROR : Port cannot contain spaces !")
        else:
            raise ValueError("PORT ERROR : Port must be a number between 0 and 65535 !")

    if port < 0:
        raise ValueError("PORT ERROR : Port cannot be negative !")
    elif port > 65535:
        raise ValueError("PORT ERROR : Port cannot be greater than 65535 !")

    return [port]


def validate_port_range(input_port: str) -> List[int]:
    """
    Validate a range of ports (start-end).

    Args:
        input_port (str): Port range as a string (e.g., '20-25').

    Returns:
        List[int]: List of all port numbers in the range.

    Raises:
        ValueError: If the range is invalid.
    """
    # Split string by dash
    ports = [p.strip() for p in input_port.split("-")]

    if len(ports) != 2:
        raise ValueError("PORT ERROR : Port range must be in 'start-end' format !")
    if "" in ports:
        raise ValueError("PORT ERROR : Ports cannot be empty !")

    start_port_str, end_port_str = ports

    try:
        start_port = int(start_port_str)
    except ValueError:
        raise ValueError("PORT ERROR : Start port is invalid !")

    try:
        end_port = int(end_port_str)
    except ValueError:
        raise ValueError("PORT ERROR : End port is invalid !")

    if start_port < 0 or end_port < 0:
        raise ValueError("PORT ERROR : Ports cannot be negative !")
    if start_port > 65535 or end_port > 65535:
        raise ValueError("PORT ERROR : Ports cannot be greater than 65535 !")
    if start_port > end_port:
        raise ValueError("PORT ERROR : Start port must be <= end port !")

    # Generate list of ports
    return list(range(start_port, end_port + 1))


# -----------------------------
# IP validation
# -----------------------------
def validate_ip(ip_address: str) -> str:
    """
    Validate an IPv4 address.

    Args:
        ip_address (str) : IP address as a string.

    Returns:
        str: Validated IP address.

    Raises:
        ValueError : If the IP is invalid.
    """
    ip_address = ip_address.strip()

    if " " in ip_address:
        raise ValueError("IP ERROR : Spaces are not allowed in IP address !")

    octets = ip_address.split(".")

    if len(octets) != 4:
        raise ValueError("IP ERROR : IP address must have 4 octets !")

    for o in octets:
        try:
            value = int(o)
        except ValueError:
            raise ValueError("IP ERROR : Each octet must be numeric !")

        if not (0 <= value <= 255):
            raise ValueError("IP ERROR : Octets must be between 0 and 255 !")

    return ip_address


# -----------------------------
# Filename validation
# -----------------------------
def validate_filename(filename: str) -> str:
    """
    Validate the output JSON filename.

    Only allows letters, numbers, underscores, dashes, and periods.
    Must end with .json.

    Args:
        filename (str) : Filename string.

    Returns:
        str: Validated filename.

    Raises:
        ValueError : If filename is invalid.
    """
    filename = filename.strip()

    if not filename.endswith(".json"):
        raise ValueError("FILE ERROR : Output file must end with .json !")

    if not re.match(r'^[A-Za-z0-9_\-\.]+$', filename):
        raise ValueError("FILE ERROR : Filename contains invalid characters !")

    return filename

# -----------------------------
# Example / test (optional)
# -----------------------------
if __name__ == "__main__":
    # This is just a small test harness; can be removed in production
    test_cases = [
        ("192.168.0.1", "80"),
        ("192.168.0.1", "20-25"),
        ("127.0.0.1", "0-65535"),
        ("256.0.0.1", "80"),   # invalid IP
        ("192.168.0.1", "-1"), # invalid port
    ]

    for ip, ports in test_cases:
        try:
            ip_valid = validate_ip(ip)
            try:
                port_list = validate_port_range(ports)
            except ValueError:
                port_list = validate_port(ports)
            print(f"{ip_valid} -> {port_list}")
        except ValueError as e:
            print(f"Error for {ip}, {ports}: {e}")