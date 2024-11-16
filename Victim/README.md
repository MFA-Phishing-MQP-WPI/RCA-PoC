# `Victim` / `Client`

## Goal
### Connect to `login.microsoft.com` and start `HTTPS-Encrypted communication`

<br>

## Run With:
```bash
.../RCA-PoC/Victim > python3 victim_shell.py
```

<br>

## `Victim Shell` Workflow

1. Connect to Wi-Fi Network (`access point shell`) to get access to the internet
2. Request DNS resolution for URL: `login.microsoft.com`
    - Receive the `IP resolved by the DNS Server` (a port number for the purposes of PoC)
3. Connect to and request the `SSL Certificate` from the `IP resolved by the DNS Server`
    - Receive an `SSL Certificate` issued to the correct URL (`login.microsoft.com`)
    - Authenticate the `SSL Certificate` using a `Root Certificate Authority`
        - `Root Certificate Authorities` can be found in `.../RCA-PoC/Victim/RootCertificates`
4. Complete [`Diffie–Hellman Key Exchange`](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange) with the `IP resolved by the DNS Server` to begin `HTTPS-Encrypted communication`.
5. Send an `HTTPS` message to the `IP resolved by the DNS Server` 
6. Receive an `HTTPS` message from the `IP resolved by the DNS Server` 
