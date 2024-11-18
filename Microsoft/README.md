# Microsoft Server

## Goal
To send contents in [`Data.txt`](Data.txt) to client via `HTTPS` secure tcp communication

<br>

## Run With
```bash
.../RCA-PoC/Microsoft > python3 microsoft_shell.py
```

<br>

## Steps
1. Waits for connection
2. Sends [`SSL Certificate`](microsoft_tls_certificate.json) to requesting party
3. Runs `Diffie-Hellman key handshake` when asked
4. Communicates using encrypted HTTPS when `Diffie-Hellman key handshake` is successful
