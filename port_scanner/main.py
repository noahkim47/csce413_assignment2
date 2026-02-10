#!/usr/bin/env python3
"""
Port Scanner - Starter Template for Students
Assignment 2: Network Security

This is a STARTER TEMPLATE to help you get started.
You should expand and improve upon this basic implementation.

TODO for students:
1. Implement multi-threading for faster scans
2. Add banner grabbing to detect services
3. Add support for CIDR notation (e.g., 192.168.1.0/24)
4. Add different scan types (SYN scan, UDP scan, etc.)
5. Add output formatting (JSON, CSV, etc.)
6. Implement timeout and error handling
7. Add progress indicators
8. Add service fingerprinting
"""

import socket
import sys
import argparse
import time
import json
import csv
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

KNOWN_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    2222: "SSH-Alt", 3306: "MySQL", 5000: "Flask", 5001: "Flask/HTTP",
    5900: "VNC", 6379: "Redis", 8080: "HTTP-Proxy", 8888: "HTTP-Alt",
    9200: "Elasticsearch", 27017: "MongoDB",
}


def grab_banner(sock, port):
    """
    Attempt to grab a service banner from an open port.

    Args:
        sock (socket): Connected socket
        port (int): Port number to probe

    Returns:
        str: Banner string or empty string
    """
    try:
        #send a GET for http services, otherwise just nudge it
        if port in (80, 443, 5000, 5001, 8080, 8443, 8888):
            sock.sendall(b"GET / HTTP/1.0\r\nHost: target\r\n\r\n")
        else:
            sock.sendall(b"\r\n")
        sock.settimeout(2)
        data = sock.recv(1024)
        if data:
            banner = data.decode("utf-8", errors="replace").strip()
            return banner[:200] if len(banner) > 200 else banner
    except (socket.timeout, ConnectionResetError, BrokenPipeError, OSError):
        pass
    return ""


def identify_service(banner, port):
    #try to figure out the service from the banner text
    if banner:
        b = banner.lower()
        if "ssh" in b: return "SSH"
        elif "http" in b: return "HTTP"
        elif "mysql" in b: return "MySQL"
        elif "redis" in b: return "Redis"
        elif "ftp" in b: return "FTP"
        elif "smtp" in b: return "SMTP"
    return KNOWN_SERVICES.get(port, "unknown")


def scan_port(target, port, timeout=1.5):
    """
    Scan a single port on the target host

    Args:
        target (str): IP address or hostname to scan
        port (int): Port number to scan
        timeout (float): Connection timeout in seconds

    Returns:
        dict: result with host, port, state, service, banner, time
    """
    result = {"host": target, "port": port, "state": "closed",
              "service": KNOWN_SERVICES.get(port, "unknown"), "banner": "", "time_ms": 0}

    # TODO: Create a socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # TODO: Set timeout
    sock.settimeout(timeout)
    start = time.time()

    try:
        # TODO: Try to connect to target:port
        if sock.connect_ex((target, port)) == 0:
            result["state"] = "open"
            result["time_ms"] = round((time.time() - start) * 1000, 2)
            banner = grab_banner(sock, port)
            result["banner"] = banner
            result["service"] = identify_service(banner, port)
        else:
            result["time_ms"] = round((time.time() - start) * 1000, 2)
    except socket.timeout:
        result["state"] = "filtered"
    except ConnectionRefusedError:
        result["state"] = "closed"
    except OSError as e:
        result["state"] = "error"
        result["banner"] = str(e)
    finally:
        # TODO: Close the socket
        sock.close()

    # TODO: Return True if connection successful
    return result


def scan_range(target, start_port, end_port, threads=100, timeout=1.5):
    """
    Scan a range of ports on the target host

    Args:
        target (str): IP address or hostname to scan
        start_port (int): Starting port number
        end_port (int): Ending port number
        threads (int): number of concurrent threads
        timeout (float): timeout per connection

    Returns:
        list: List of open ports
    """
    total = end_port - start_port + 1
    results = []
    completed = 0
    start_time = time.time()

    print(f"[*] Scanning {target} ports {start_port}-{end_port} ({threads} threads)")

    # TODO: Implement the scanning logic
    # Hint: Loop through port range and call scan_port()
    # Hint: Consider using threading for better performance
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(scan_port, target, p, timeout): p
                   for p in range(start_port, end_port + 1)}

        for future in as_completed(futures):
            result = future.result()
            results.append(result)
            completed += 1

            # TODO: Print progress (optional)
            if completed % 500 == 0 or completed == total:
                pct = (completed / total) * 100
                sys.stdout.write(f"\r[*] Progress: {completed}/{total} ({pct:.1f}%) - {time.time()-start_time:.1f}s")
                sys.stdout.flush()

            # TODO: If open, add to open_ports list
            if result["state"] == "open":
                banner = result["banner"][:60].replace("\n"," ").replace("\r","") if result["banner"] else ""
                sys.stdout.write(f"\n[+] OPEN {result['host']}:{result['port']} ({result['service']})")
                if banner:
                    sys.stdout.write(f" - {banner}")
                sys.stdout.write("\n")
                sys.stdout.flush()

    print(f"\n[*] Done in {time.time()-start_time:.2f}s")
    return results


def parse_ports(port_str):
    #handles stuff like 80,443,1000-2000
    ports = []
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            s, e = part.split("-", 1)
            ports.extend(range(int(s), int(e) + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))


def parse_targets(target_str):
    #supports single ip, hostname, or cidr like 172.20.0.0/24
    try:
        network = ipaddress.ip_network(target_str, strict=False)
        targets = [str(h) for h in network.hosts()]
        return targets if targets else [str(network.network_address)]
    except ValueError:
        return [target_str]


def print_table(results, scan_time):
    open_results = [r for r in results if r["state"] == "open"]
    if not open_results:
        print("\nNo open ports found.")
        return

    hosts = {}
    for r in open_results:
        hosts.setdefault(r["host"], []).append(r)

    for host, hrs in hosts.items():
        print(f"\nScan results for {host}:")
        print(f"{'PORT':<10} {'STATE':<10} {'SERVICE':<18} {'TIME(ms)':<10} BANNER")
        print("-" * 90)
        for r in sorted(hrs, key=lambda x: x["port"]):
            b = r["banner"][:50].replace("\n"," ").replace("\r","")
            print(f"{r['port']:<10} {r['state']:<10} {r['service']:<18} {r['time_ms']:<10} {b}")
        print(f"\n{len(hrs)} open port(s) on {host}")
    print(f"Scan time: {scan_time:.2f}s")


def output_json(results, fp):
    with open(fp, "w") as f:
        json.dump([r for r in results if r["state"] == "open"], f, indent=2)
    print(f"[+] JSON saved to {fp}")


def output_csv(results, fp):
    with open(fp, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["host","port","state","service","banner","time_ms"])
        w.writeheader()
        w.writerows([r for r in results if r["state"] == "open"])
    print(f"[+] CSV saved to {fp}")


def main():
    """Main function"""
    # TODO: Parse command-line arguments
    parser = argparse.ArgumentParser(description="Custom Port Scanner - CSCE 413")
    parser.add_argument("--target", "-t", required=True, help="Target IP, hostname, or CIDR range")
    parser.add_argument("--ports", "-p", default="1-10000", help="Port range (default: 1-10000)")
    parser.add_argument("--threads", "-T", type=int, default=100, help="Thread count (default: 100)")
    parser.add_argument("--timeout", type=float, default=1.5, help="Timeout in seconds (default: 1.5)")
    parser.add_argument("--output", "-o", choices=["table","json","csv"], default="table", help="Output format")
    parser.add_argument("--outfile", "-f", help="Output file path for json/csv")

    # TODO: Validate inputs
    args = parser.parse_args()
    targets = parse_targets(args.target)
    ports = parse_ports(args.ports)

    print("=" * 60)
    print("  Custom Port Scanner - CSCE 413")
    print("=" * 60)
    print(f"Target(s):  {args.target} ({len(targets)} host(s))")
    print(f"Ports:      {len(ports)} ({min(ports)}-{max(ports)})")
    print(f"Threads:    {args.threads}  |  Timeout: {args.timeout}s")
    print(f"Started:    {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    # TODO: Call scan_range()
    all_results = []
    scan_start = time.time()

    for target in targets:
        all_results.extend(scan_range(target, min(ports), max(ports), args.threads, args.timeout))

    total_time = time.time() - scan_start

    # TODO: Display results
    print_table(all_results, total_time)

    if args.output == "json":
        output_json(all_results, args.outfile or "scan_results.json")
    elif args.output == "csv":
        output_csv(all_results, args.outfile or "scan_results.csv")


if __name__ == "__main__":
    main()