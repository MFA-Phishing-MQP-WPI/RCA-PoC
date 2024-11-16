# `Wi-Fi Network` / `Wi-Fi Access Point`
##### Uses threads to handle up to `32 clients` (`64 paries`) at once

## Features
 - Sniffs all packets and saves them to [sniffed_packets.txt](sniffed_packets.txt)

<br>

## Modes

<br>

1. `WAP` (`Wifi Access Point`)
    - Accepts and forwards communication between two parties

<br>

2. `RWAP` (`Rogue Wifi Access Point`)
    - Accepts and forwards communication between two parties
    - If the response originates from a `DNS Server` and the request was a `DNS Resolution Request` for `URL="login.microsoft.com"`
        - The response is edited by `RWAP` before forwarding, and the edited response is forwarded back to the `Victim` / `Client` replacing the original resolution response

<br>

3. `RWAP` (`Rogue Wifi Access Point`) With `-require_malicious_ca` Flag On
    - ~~Accepts and~~ Forwards comunication between two parties
    - Only accepts connections from `Victim`s / `Client`s that have required `Malicious Certificate` (`MCA`) installed as a `Root Certificate Authority`
        - Responds to `MCA Download Requests` with the `Malicious Certificate` (`MCA`) in bytes
    - If the response originates from a `DNS Server` and the request was a `DNS Resolution Request` for `URL="login.microsoft.com"`
        - The response is edited by `RWAP` and the edited response is forwarded to the `Victim` / `Client`

<br>

<br>

## Run With:
```bash
.../RCA-PoC/WiFi_Access_Point > python3 access_point_shell.py [wap rwap] [OPTIONAL: -require_malicious_ca]
```

<br>

<br>

## `Victim Shell` Workflow
1. Allow connections if connection requirements are met
2. Forward requests and responses between parties
    - Edit responses if mode is `RWAP` and other requirements are present (see [Modes](#Modes) for more info)
3. Sniff all packets
    - All sniffed packets saved to [sniffed_packets.txt](sniffed_packets.txt)



