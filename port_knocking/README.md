## Port Knocking

Protects SSH on port 2222. Port is blocked by default via iptables and only opens after the correct knock sequence.

### How it works
1. Server blocks port 2222 and listens on knock ports (1234, 5678, 9012)
2. Client sends TCP connections to knock ports in order
3. Server validates sequence within a 10s timing window
4. Correct sequence opens port 2222 for that client IP for 30 seconds
5. Wrong sequence or timeout resets progress

### Usage
```bash
# Server
python3 knock_server.py --sequence 1234,5678,9012 --protected-port 2222

# Client
python3 knock_client.py --target 172.20.0.40 --sequence 1234,5678,9012 --check

# Demo
bash demo.sh 172.20.0.40 1234,5678,9012 2222
```