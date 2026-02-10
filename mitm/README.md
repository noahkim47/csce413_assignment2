## MITM Attack

### Vulnerability
The webapp communicates with MySQL over an unencrypted connection. SSL is disabled in the docker compose config (MYSQL_SSL: false, SQLALCHEMY_SSL_MODE: DISABLED), so all SQL queries and responses are transmitted in plaintext.

### Methodology
1. Identified the Docker bridge interface using `ip link | grep br-`
2. Ran tcpdump to capture traffic on port 3306: `sudo tcpdump -i br-XXXX -A -s 0 'port 3306'`
3. Generated traffic by accessing `curl http://localhost:5001/api/secrets`
4. Observed plaintext SQL queries and responses in the tcpdump output

### Findings
The captured traffic contained a SELECT query on the secrets table. The response included an API token in plaintext:
- FLAG{n3tw0rk_tr4ff1c_1s_n0t_s3cur3}

This token was used as a Bearer token to authenticate to the secret API at port 8888, which returned:
- FLAG{p0rt_kn0ck1ng_4nd_h0n3yp0ts_s4v3_th3_d4y}

### Evidence
- tcpdump_capture.png: tcpdump output showing plaintext SQL query and API token
- api_secrets.png: curl response from /api/secrets endpoint
- flag_capture.png: response from secret API after authenticating with the token

### Impact
Anyone on the same network can read all database traffic including user data, credentials, and API tokens.