# Honeypot Analysis

## Summary of Observed Attacks
After deploying the SSH honeypot on port 22, test attacks were run:

1. `ssh admin@localhost -p 22` — captured client banner and connection metadata
2. Multiple login attempts with common usernames (admin, root, test) — all logged with timestamps and source IPs
3. Netcat probes with `nc localhost 22` — honeypot responded with SSH banner and logged raw data

## Notable Patterns
- Connection durations varied from <1s (automated probes) to several seconds (interactive attempts)
- Client SSH version strings were captured, which can fingerprint attacker tools
- Repeated connection attempts from the same IP were logged individually

## Recommendations
- Deploy honeypots on commonly targeted ports (22, 23, 3389) to catch recon activity early
- Feed logs into a SIEM or alerting system for real-time detection
- Use captured IPs to build blocklists or trigger automated firewall rules