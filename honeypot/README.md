## SSH Honeypot

Fake SSH server that logs all connection attempts including source IPs, client banners, data sent, and connection duration.

### How it works
1. Binds to port 22 and sends a realistic OpenSSH 8.9p1 banner
2. Accepts connections and reads client data across multiple rounds
3. Logs everything to `logs/connections.jsonl` as structured JSON
4. Each connection handled in its own thread

### Usage
```bash
# Run via docker compose
docker compose up honeypot

# Test attacks
ssh admin@localhost -p 2222
nc localhost 2222

# View logs
cat honeypot/logs/honeypot.log
cat honeypot/logs/connections.jsonl
```