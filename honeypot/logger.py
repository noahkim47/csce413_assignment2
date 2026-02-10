"""Logging helpers for the honeypot."""

import json
import os
import threading
from datetime import datetime


class HoneypotLogger:

    def __init__(self, filepath):
        self.filepath = filepath
        self.lock = threading.Lock()
        os.makedirs(os.path.dirname(filepath), exist_ok=True)

    def log_connection(self, src_ip, src_port, client_banner="", data=None, duration=0):
        #each connection gets one json line
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "src_ip": src_ip,
            "src_port": src_port,
            "client_banner": client_banner,
            "data_received": data or [],
            "duration_seconds": duration,
        }

        with self.lock:
            with open(self.filepath, "a") as f:
                f.write(json.dumps(entry) + "\n")

    def get_stats(self):
        if not os.path.exists(self.filepath):
            return {"total": 0, "unique_ips": 0}

        ips = set()
        total = 0
        with open(self.filepath) as f:
            for line in f:
                try:
                    entry = json.loads(line)
                    total += 1
                    ips.add(entry["src_ip"])
                except json.JSONDecodeError:
                    continue

        return {"total": total, "unique_ips": len(ips)}