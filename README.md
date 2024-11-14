# Rogue Certificate Authority (RCA) - Proof of Concept

This repository contains a Proof of Concept (PoC) for demonstrating a simulated network environment where a victim device interacts with DNS, a Wi-Fi access point, and a Microsoft server over a secure HTTPS connection. Each component simulates real-world protocols like DNS resolution, TLS certification, and Diffie-Hellman key exchange.

## Requirements

- Python 3.6+
- `cryptography` package

Install the required Python package using:
```bash
pip install cryptography
```

## Setup and Running the PoC

To run this PoC, you’ll need four terminals (or terminal windows) set up in four different directories, each containing the relevant Python scripts.

Watch the [5-minute walkthrough](https://www.youtube.com/watch?v=-w1Ib0YH9nc) or follow the steps below.

1. **Clone the repository**:
    ```bash
    git clone https://github.com/MFA-Phishing-MQP-WPI/RCA-PoC.git
    ```

<br>

2. **Running each component**:
   Open a new terminal for each directory and run the respective scripts:

   **Terminal 1** - `Microsoft Server` / `Fake Microsoft Server`:
   ```bash
   cd RCA-PoC/Microsoft
   python3 microsoft_shell.py
   ```
   ### OR
   
   ```bash
   cd RCA-PoC/NotMicrosoft
   python3 microsoft_shell.py
   ```
    
    <br>
    
   **Terminal 2** - `Wi-Fi Access Point`:
   ```bash
   cd RCA-PoC/WiFi_Access_Point
   python3 access_point_shell.py [wap rwap] [OPTIONAL: -require_malicious_ca]
   ```

   <br>
   
   **Terminal 3** - `DNS Server`:
   ```bash
   cd RCA-PoC/DNS
   python3 dns_server.py
   ```
    
    <br>
    
   **Terminal 4** - `Victim`:
   ###### basic:
   ```bash
   cd RCA-PoC/Victim
   python3 victim_shell.py 
   ```
   ###### verbose:
   ```bash
   cd RCA-PoC/Victim
   python3 victim_shell.py -v
   ```

<br>

4. **Expected Flow**:
    1. In the case where the Wi-Fi Access Point is running in `WAP` mode
       - The `Victim` first tries to connect to the `access point`.
           - The `access point` grants the `victim` access.
       - The `victim` connects to the `DNS server` through the `access point`, requesting to resolve `login.microsoft.com`.
           - The `DNS server` responds with the `port` for the `Microsoft server`.
       - The `Victim` then requests a `TLS certificate` from the `Microsoft server`, which the `access point` forwards.
       - The `Victim` verifies the certificate and initiates a `Diffie-Hellman key exchange`.
       - Finally, the victim sends an `HTTPS-encrypted message` to the `Microsoft server`, which decrypts the message and responds.
       
         ✅ **HTTPS SUCCESS** 🔒
    
    <br>
    
    2. In the case where the Wi-Fi Access Point is running in `RWAP` mode
       - The `Victim` first tries to connect to the `access point`.
           - The `access point` grants the `victim` access.
       - The `victim` connects to the `DNS server` through the `access point`, requesting to resolve `login.microsoft.com`.
           - The `DNS server` responds **to the `Access Point`** with the `port` for the `Microsoft server`.
           - The `Access Point` edits the resolved port to the `Malicious Server` and forwards the edited response to the `Victim`.
       - The `Victim` then requests a `TLS certificate` from the `Malicious server` thinking it's the `Microsoft Server`, which the `access point` forwards.
       - The `Victim` **fails** to verify the fake certificate and terminates the communication.
       
         ❌ **HTTPS FAILURE** ❌
    
    <br>
    
    3. In the case where the Wi-Fi Access Point is running in `RWAP` mode with the `-require_malicious_ca` flag
       - The `Victim` first tries to connect to the `access point`.
           - The `access point` denies the `victim` access due to a missing certificate.
       - The `Victim` requests the missing certificate from the `access point`.
           - The `Victim` installs the `malicious CA` received from the `access point`.
       - The `Victim` tries to connect to the `access point` a second time.
           - The `access point` grants the `victim` access.
       - The `Victim` connects to the `DNS server` through the `access point`, requesting to resolve `login.microsoft.com`.
           - The `DNS server` responds **to the `Access Point`** with the `port` for the `Microsoft server`.
           - The `Access Point` edits the resolved port to the `Malicious Server` and forwards the edited response to the `Victim`.
       - The `Victim` then requests a `TLS certificate` from the `Malicious server` thinking it's the `Microsoft Server`, which the `access point` forwards.
       - The `Victim` verifies the fake certificate using the `malicious CA` that was installed when the `Victim` connected to the `access point` and initiates a `Diffie-Hellman key exchange`.
       - Finally, the victim sends an `HTTPS-encrypted message` to the `Malicious server`, which decrypts the message and responds.
       
         ✅ **HTTPS SUCCESS** 🔒
    
    <br>
    
       

<br>

## Components

The PoC is broken into four main components, each running in its own terminal session:
1. **Microsoft Server** (`Microsoft`): Acts as the target server, handling requests from the victim via the access point, providing TLS certificates, and securely communicating via Diffie-Hellman.
2. **Wi-Fi Access Point** (`WiFi_Access_Point`): Intercepts and forwards communication between the victim and the Microsoft and DNS servers.
3. **DNS Server** (`DNS`): Resolves the URL requested by the victim to an IP address and port.
4. **Victim Device** (`Victim`): The main client initiating requests to resolve a URL, connect to the Microsoft server, authenticate via a TLS certificate, exchange keys, and establish a secure communication channel.

<br>

## Overview of PoC Process

1. **DNS Resolution**: The victim requests the IP and port for `login.microsoft.com` from the DNS server via the access point. The DNS server responds with the port of the Microsoft server.
   
2. **TLS Authentication**: The victim requests the Microsoft server’s TLS certificate via the access point. The victim verifies the authenticity of the certificate.
   
3. **Diffie-Hellman Key Exchange**: The victim initiates a secure Diffie-Hellman key exchange with the Microsoft server, establishing a shared secret key.
   
4. **Secure Communication**: Using the shared key, the victim sends an encrypted HTTPS message to the Microsoft server, which decrypts it and responds.

## Purpose of the PoC

This PoC simulates an environment where multiple interactions occur through a central access point, emulating a scenario where a Wi-Fi access point intermediates communication between a client and external servers. It demonstrates:
- **DNS Resolution** over an intermediary.
- **TLS Certificate Verification** and the role of certificates in authenticating a server.
- **Diffie-Hellman Key Exchange** to establish a secure session key.
- **Encrypted Communication** via HTTPS using the established session key.

This setup showcases how various protocols work together to establish secure and authenticated communication channels over a potentially untrusted network intermediary.

**Note**: This PoC is for demonstration purposes only. Do not deploy this code on live networks.
