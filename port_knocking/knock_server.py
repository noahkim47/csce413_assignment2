#!/usr/bin/env python3
"""Starter template for the port knocking server."""

import argparse
import logging
import socket
import subprocess
import threading
import time

DEFAULT_KNOCK_SEQUENCE = [1234, 5678, 9012]
DEFAULT_PROTECTED_PORT = 2222
DEFAULT_SEQUENCE_WINDOW = 10.0


def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[logging.StreamHandler()],
    )


def run_cmd(cmd):
    try:
        subprocess.run(cmd, shell=True, check=True, capture_output=True)
        return True
    except subprocess.CalledProcessError as e:
        logging.error("Command failed: %s -> %s", cmd, e.stderr.decode())
        return False


def open_protected_port(protected_port, client_ip):
    # TODO: Use iptables/nftables to allow access to protected_port.
    run_cmd(f"iptables -I INPUT -s {client_ip} -p tcp --dport {protected_port} -j ACCEPT")
    logging.info("Opened port %s for %s", protected_port, client_ip)


def close_protected_port(protected_port, client_ip):
    # TODO: Remove firewall rules for protected_port.
    run_cmd(f"iptables -D INPUT -s {client_ip} -p tcp --dport {protected_port} -j ACCEPT")
    logging.info("Closed port %s for %s", protected_port, client_ip)


def block_protected_port(protected_port):
    #drop everything to protected port by default
    run_cmd(f"iptables -A INPUT -p tcp --dport {protected_port} -j DROP")
    logging.info("Blocked port %s by default", protected_port)


def auto_close(protected_port, client_ip, timeout=30):
    #closes the port after timeout so it doesnt stay open forever
    time.sleep(timeout)
    close_protected_port(protected_port, client_ip)


def listen_on_port(port, callback):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(1.0)
    sock.bind(("0.0.0.0", port))
    sock.listen(1)

    while True:
        try:
            conn, addr = sock.accept()
            callback(addr[0], port)
            conn.close()
        except socket.timeout:
            continue
        except OSError:
            break


def listen_for_knocks(sequence, window_seconds, protected_port):
    """Listen for knock sequence and open the protected port."""
    logger = logging.getLogger("KnockServer")
    logger.info("Listening for knocks: %s", sequence)
    logger.info("Protected port: %s", protected_port)

    block_protected_port(protected_port)

    # TODO: Track each source IP and its progress through the sequence.
    # TODO: Enforce timing window per sequence.
    # TODO: On correct sequence, call open_protected_port().
    # TODO: On incorrect sequence, reset progress.
    clients = {} #{ip: {"index": int, "start_time": float}}
    lock = threading.Lock()

    def handle_knock(client_ip, port):
        with lock:
            now = time.time()

            if client_ip not in clients:
                clients[client_ip] = {"index": 0, "start_time": now}

            state = clients[client_ip]

            #check if they took too long
            if now - state["start_time"] > window_seconds:
                logger.info("Window expired for %s, resetting", client_ip)
                clients[client_ip] = {"index": 0, "start_time": now}
                state = clients[client_ip]

            expected_port = sequence[state["index"]]

            if port == expected_port:
                state["index"] += 1
                logger.info("Correct knock from %s: port %d (%d/%d)",
                            client_ip, port, state["index"], len(sequence))

                if state["index"] == len(sequence):
                    logger.info("Sequence complete for %s! Opening port %d",
                                client_ip, protected_port)
                    open_protected_port(protected_port, client_ip)
                    #auto close after 30s in background
                    threading.Thread(target=auto_close,
                                     args=(protected_port, client_ip, 30),
                                     daemon=True).start()
                    del clients[client_ip]
            else:
                logger.info("Wrong knock from %s: got %d, expected %d. Resetting.",
                            client_ip, port, expected_port)
                del clients[client_ip]

    # TODO: Create TCP listeners for each knock port.
    threads = []
    for port in sequence:
        t = threading.Thread(target=listen_on_port, args=(port, handle_knock), daemon=True)
        t.start()
        threads.append(t)
        logger.info("Listening on knock port %d", port)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Shutting down")


def parse_args():
    parser = argparse.ArgumentParser(description="Port knocking server starter")
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
        "--window",
        type=float,
        default=DEFAULT_SEQUENCE_WINDOW,
        help="Seconds allowed to complete the sequence",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    setup_logging()

    try:
        sequence = [int(port) for port in args.sequence.split(",")]
    except ValueError:
        raise SystemExit("Invalid sequence. Use comma-separated integers.")

    listen_for_knocks(sequence, args.window, args.protected_port)


if __name__ == "__main__":
    main()