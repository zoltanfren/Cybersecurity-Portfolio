"""
scan_iterator.py

Responsible for iterating over a list of ports and scanning them concurrently.

Features :
- Uses ThreadPoolExecutor for multithreading.
- Supports rate limiting (max connections per second).
- Returns a list of tuples (port, is_open).
"""

from typing import List, Tuple
from .socket_connection import socket_connection
import time
from concurrent.futures import ThreadPoolExecutor
from itertools import repeat
from threading import Lock
import logging

# -----------------------------
# Rate limiter class
# -----------------------------
class RateLimiter:
    """
    Thread-safe rate limiter to control the number of scans per second.

    Attributes :
        interval (float) : Minimum time (in seconds) between scan attempts.
        lock (Lock) : Ensures only one thread updates next_allowed_time at a time.
        next_allowed_time (float) : Monotonic time for the next allowed scan.

    Example :
        rate_limiter = RateLimiter(rate=10.0)  # 10 scans/sec max
        rate_limiter.wait()  # wait until allowed to scan
    """

    def __init__(self, rate: float) -> None:
        if rate <= 0:
            raise ValueError("Rate must be greater than 0")

        self.interval = 1.0 / rate
        self.lock = Lock()
        self.next_allowed_time = time.monotonic()

    def wait(self) -> None:
        """
        Waits until the next allowed scan time according to rate limit.
        Ensures all threads respect the global rate limit.
        """
        with self.lock:
            now = time.monotonic()
            if now < self.next_allowed_time:
                time.sleep(self.next_allowed_time - now)
            # Schedule next allowed time
            self.next_allowed_time = max(self.next_allowed_time + self.interval, time.monotonic())

# -----------------------------
# Single port scan
# -----------------------------
def scan_port(ip: str, port: int, limiter: RateLimiter, timeout: float) -> Tuple[int, bool]:
    """
    Scans a single TCP port on a target IP, respecting rate limits.

    Args :
        ip (str) : Target IP address.
        port (int) : Target port number.
        limiter (RateLimiter) : Shared rate limiter instance.
        timeout (float) : Socket timeout in seconds.

    Returns :
        Tuple[int, bool] : (port, True if open, False if closed)
    """
    limiter.wait()  # enforce global rate limit
    return socket_connection(ip, port, timeout)


# -----------------------------
# Main scan iterator
# -----------------------------
def scan_iterator(ip_address: str,
                  ports: List[int],
                  max_threads: int,
                  max_connections_per_sec: float,
                  timeout: float) -> List[Tuple[int, bool]]:
    """
    Loops through a list of ports and attempts to connect to each of them on the specified IP address.

    Args :
        ip_address (str) : Target IP address.
        ports (List[int]) : List of ports to scan.
        max_threads (int) : Maximum concurrent threads.
        max_connections_per_sec (float) : Max total connection attempts per second.
        timeout (float) : Socket timeout in seconds.

    Returns:
        List[Tuple[int, bool]] : List of (port, status) tuples where status=True if port is open.
    """
    if not ports:
        return []

    logging.info(
        f"Starting port scan on {ip_address} ports {ports[0]}-{ports[-1]} "
        f"with max threads: {max_threads}, max connections/sec: {max_connections_per_sec}"
    )

    start_time = time.time()
    rate_limiter = RateLimiter(max_connections_per_sec)

    # Use ThreadPoolExecutor to scan ports concurrently
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        # repeat(ip_address) and repeat(timeout) create a value for each port
        # executor.map preserves port order in results
        output_port_list: List[Tuple[int, bool]] = list(
            executor.map(scan_port, repeat(ip_address), ports, repeat(rate_limiter), repeat(timeout))
        )

    elapsed_time = time.time() - start_time
    logging.info(f"Port scan finished in {elapsed_time:.5f} seconds")

    return output_port_list