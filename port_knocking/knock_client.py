#!/usr/bin/env python3
"""Starter template for the port knocking client."""

import argparse
import socket
import time

DEFAULT_KNOCK_SEQUENCE = [1234, 5678, 9012]
DEFAULT_PROTECTED_PORT = 2222
DEFAULT_DELAY = 0.3


def send_knock(target, port, delay):
    """Send a single knock to the target port."""
    # TODO: Choose UDP or TCP knocks based on your design.
    try:
        with socket.create_connection((target, port), timeout=1.0):
            pass
    except OSError:
        pass #connection refused is fine, knock still registers
    print(f"[*] Knocked on port {port}")
    time.sleep(delay)


def perform_knock_sequence(target, sequence, delay):
    """Send the full knock sequence."""
    print(f"[*] Sending knock sequence to {target}: {sequence}")
    for port in sequence:
        send_knock(target, port, delay)
    print("[+] Knock sequence complete")


def check_protected_port(target, protected_port):
    """Try connecting to the protected port after knocking."""
    # TODO: Replace with real service connection if needed.
    time.sleep(0.5) #give server a sec to process
    try:
        with socket.create_connection((target, protected_port), timeout=3.0) as s:
            banner = s.recv(1024).decode("utf-8", errors="replace").strip()
            print(f"[+] Connected to protected port {protected_port}")
            if banner:
                print(f"[+] Banner: {banner}")
    except OSError:
        print(f"[-] Could not connect to protected port {protected_port}")


def parse_args():
    parser = argparse.ArgumentParser(description="Port knocking client starter")
    parser.add_argument("--target", required=True, help="Target host or IP")
    parser.add_argument(
        "--sequence",
        default=",".join(str(port) for port in DEFAULT_KNOCK_SEQUENCE),
        help="Comma-separated knock ports",
    )
    parser.add_argument(
        "--protected-port",
        type=int,
        default=DEFAULT_PROTECTED_PORT,
        help="Protected service port",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=DEFAULT_DELAY,
        help="Delay between knocks in seconds",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Attempt connection to protected port after knocking",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    try:
        sequence = [int(port) for port in args.sequence.split(",")]
    except ValueError:
        raise SystemExit("Invalid sequence. Use comma-separated integers.")

    perform_knock_sequence(args.target, sequence, args.delay)

    if args.check:
        check_protected_port(args.target, args.protected_port)


if __name__ == "__main__":
    main()