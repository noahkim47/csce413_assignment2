#!/usr/bin/env python3
"""Starter template for the honeypot assignment."""

import logging
import os
import socket
import threading
import time
from logger import HoneypotLogger

LOG_PATH = "/app/logs/honeypot.log"
CONNECTIONS_PATH = "/app/logs/connections.jsonl"
BIND_HOST = "0.0.0.0"
BIND_PORT = 22

#looks like a real ubuntu ssh server
SSH_BANNER = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.13\r\n"


def setup_logging():
    os.makedirs("/app/logs", exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[logging.FileHandler(LOG_PATH), logging.StreamHandler()],
    )


def handle_client(conn, addr, hp_logger):
    # TODO: Implement protocol simulation, logging, and alerting.
    client_ip, client_port = addr
    start_time = time.time()
    logger = logging.getLogger("Honeypot")
    logger.info("Connection from %s:%d", client_ip, client_port)

    try:
        #send fake banner first
        conn.sendall(SSH_BANNER)

        #read what the client sends back
        conn.settimeout(10)
        client_banner = ""
        try:
            data = conn.recv(1024)
            if data:
                client_banner = data.decode("utf-8", errors="replace").strip()
                logger.info("Client banner from %s: %s", client_ip, client_banner)
        except socket.timeout:
            pass

        #try to grab more data from them
        collected_data = []
        for _ in range(3):
            try:
                conn.settimeout(15)
                data = conn.recv(4096)
                if not data:
                    break
                decoded = data.decode("utf-8", errors="replace").strip()
                if decoded:
                    collected_data.append(decoded)
                    logger.info("Data from %s: %s", client_ip, decoded[:200])
            except socket.timeout:
                break
            except (ConnectionResetError, BrokenPipeError):
                break

        duration = round(time.time() - start_time, 2)

        hp_logger.log_connection(
            src_ip=client_ip,
            src_port=client_port,
            client_banner=client_banner,
            data=collected_data,
            duration=duration,
        )

    except Exception as e:
        logger.error("Error handling %s: %s", client_ip, e)
    finally:
        try:
            conn.close()
        except OSError:
            pass


def run_honeypot():
    logger = logging.getLogger("Honeypot")
    hp_logger = HoneypotLogger(CONNECTIONS_PATH)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((BIND_HOST, BIND_PORT))
    sock.listen(10)

    logger.info("SSH Honeypot listening on %s:%d", BIND_HOST, BIND_PORT)

    try:
        while True:
            conn, addr = sock.accept()
            #each connection gets its own thread
            t = threading.Thread(target=handle_client, args=(conn, addr, hp_logger), daemon=True)
            t.start()
    except KeyboardInterrupt:
        logger.info("Shutting down")
    finally:
        sock.close()


if __name__ == "__main__":
    setup_logging()
    run_honeypot()