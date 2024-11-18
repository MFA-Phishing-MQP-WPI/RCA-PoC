# Microsoft Server

## Goal
1. Impersonate `login.microsoft.com`
2. Send contents in [`Data.txt`](Data.txt) to client via `HTTPS` secure tcp communication

<br>

## Run With
```bash
.../RCA-PoC/NotMicrosoft > python3 not_microsoft_shell.py
```

<br>

## Steps
1. Waits for connection
2. Sends [`Malicious SSL Certificate`](malicious_microsoft_tls_certificate.json) to requesting party 
3. Runs `Diffie-Hellman key handshake` when asked
4. Communicates using encrypted HTTPS when `Diffie-Hellman key handshake` is successful
