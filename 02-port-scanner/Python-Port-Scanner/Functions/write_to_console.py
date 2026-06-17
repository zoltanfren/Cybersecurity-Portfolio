"""
write_to_console.py

Handles printing port scan results to the console in a formatted table.

Features :
- Shows IP, port, status (OPEN/CLOSED), and common service name if known.
- Simple, human-readable output for quick scanning feedback.
"""

from typing import List, Tuple

# Mapping of common ports to services
COMMON_PORTS = {
    20: "FTP", 21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
    119: "NNTP", 123: "NTP", 143: "IMAP", 161: "SNMP",
    179: "BGP", 443: "HTTPS", 465: "SMTPS", 500: "ISAKMP",
    587: "SMTP", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle", 2049: "NFS",
    2082: "cPanel", 2083: "cPanel SSL", 2086: "WHM",
    2087: "WHM SSL", 2181: "Zookeeper", 2222: "DirectAdmin",
    2375: "Docker", 2376: "Docker SSL", 2483: "Oracle TCPS",
    2484: "Oracle", 3000: "Dev Server", 3306: "MySQL",
    3389: "RDP", 3690: "Subversion", 4444: "Metasploit",
    4567: "Ruby", 5000: "Flask", 5060: "SIP",
    5432: "PostgreSQL", 5601: "Kibana", 5672: "RabbitMQ",
    5900: "VNC", 5985: "WinRM", 5986: "WinRM SSL",
    6379: "Redis", 6443: "Kubernetes", 6667: "IRC",
    7001: "WebLogic", 7002: "WebLogic SSL",
    7199: "Cassandra", 7474: "Neo4j", 8000: "HTTP Alt",
    8008: "HTTP Proxy", 8009: "AJP13", 8080: "HTTP Proxy",
    8081: "HTTP Alt", 8088: "Hadoop", 8090: "HTTP Alt",
    8161: "ActiveMQ", 8200: "Vault", 8333: "Bitcoin",
    8443: "HTTPS Alt", 8500: "Consul", 8761: "Eureka",
    8888: "Jupyter", 9000: "SonarQube", 9042: "Cassandra",
    9092: "Kafka", 9093: "Kafka SSL", 9200: "Elasticsearch",
    9418: "Git", 9999: "Debug"
}

# -----------------------------
# Console output function
# -----------------------------
def write_to_console(ip_address: str, scan_result: List[Tuple[int, bool]]) -> None:
    """
    Prints a formatted table of port scan results to the console.

    Args :
        ip_address (str) : Target IP address.
        scan_result (List[Tuple[int, bool]]) : List of tuples (port, is_open)

    Example :
        write_to_console("192.168.1.1", [(21, True), (22, False)])
    """
    print("\nScan Results")
    print("-" * 60)
    print(f"{'IP':<15}{'PORT':<10}{'STATUS':<10}{'COMMON PORT'}")
    print("-" * 60)

    for port, status in scan_result:
        state = "OPEN" if status else "CLOSED"
        common = COMMON_PORTS.get(port, "No")
        print(f"{ip_address:<15}{port:<10}{state:<10}{common}")


# -----------------------------
# Example usage
# -----------------------------
if __name__ == "__main__":
    ip_address = "192.168.1.1"
    scan_results = [
        (21, True),
        (22, False),
        (23, False),
        (80, True),
        (8761, False),
        (26, True)
    ]

    write_to_console(ip_address, scan_results)