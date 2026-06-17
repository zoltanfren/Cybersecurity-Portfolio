"""
store_to_file.py

Handles storing port scan results to a JSON file.

Features :
- Converts a list of tuples (port, status) into a JSON list of dictionaries.
- Each dictionary contains: IP address, port number, and status ("OPEN"/"CLOSED").
- Indented JSON for readability.
"""

import json
from typing import List, Tuple

# -----------------------------
# Store scan results to JSON
# -----------------------------
def store_to_file(ip_address: str, scan_result: List[Tuple[int, bool]], filename: str) -> None:
    """
    Stores port scan results in a JSON file.

    Args :
        ip_address (str): The scanned IP address.
        scan_result (List[Tuple[int, bool]]): List of (port, status) tuples.
        filename (str): Output JSON file name.

    Returns :
        None

    Example :
        store_to_file("192.168.1.1", [(21, True), (22, False)], "results.json")
    """
    data = []

    # Convert tuple list to list of dictionaries for JSON
    for port, status in scan_result:
        data.append({
            "ip": ip_address,
            "port": port,
            "status": "OPEN" if status else "CLOSED"
        })

    # Write to file
    with open(filename, "w") as file:
        json.dump(data, file, indent=4)

# -----------------------------
# Example usage
# -----------------------------
if __name__ == "__main__":
    ip_address = "192.168.1.1"
    results = [
        (21, True),
        (22, False),
        (23, False),
        (80, True)
    ]
    store_to_file(ip_address, results, "scan_results.json")
    print("Scan results saved to scan_results.json")