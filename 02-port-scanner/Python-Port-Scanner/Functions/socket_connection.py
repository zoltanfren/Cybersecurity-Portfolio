"""
socket_connection.py

Handles the actual TCP connection to a single port.

This module:
- Attempts to connect to a target IP:port.
- Uses socket timeouts to avoid hanging.
- Returns a tuple (port, status) where status is True if open, False if closed.
"""

from typing import Tuple
import socket
import logging

# -----------------------------
# Single port connection
# -----------------------------
def socket_connection(ip_address: str, port: int, timeout: float) -> Tuple[int, bool]:
    """
    Attempt to connect to a single TCP port on a target IP.

    Args:
        ip_address (str) : Target IPv4 address.
        port (int) : TCP port to scan.
        timeout (float) : Socket timeout in seconds.

    Returns:
        Tuple[int, bool] : (port, True if open, False if closed)

    Notes:
        - Uses context manager `with` to automatically close the socket.
        - Catches name resolution errors and network/socket errors.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)  # Set socket timeout
            result = sock.connect_ex((ip_address, port))  # 0 if success, otherwise error code
            is_open = (result == 0)

            # Logging for debugging
            if is_open:
                logging.debug(f"Finished scanning {ip_address}:{port} - OPEN")
            else:
                logging.debug(f"Finished scanning {ip_address}:{port} - CLOSED")

            return (port, is_open)

    # Name resolution failed
    except socket.gaierror:
        logging.debug(f"Scan aborted for {ip_address}:{port} - name resolution failed")
        return (port, False)

    # Other network/socket errors
    except OSError:
        logging.debug(f"Scan aborted for {ip_address}:{port} - network/socket error")
        return (port, False)