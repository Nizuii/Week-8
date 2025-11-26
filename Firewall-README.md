# Types of Firewall

## 1. Traditional firewall
- A traditional (stateful) firewall filters traffic mainly using IP addresses, ports, and protocols, sometimes with simple state tracking of connections. It does not understand application payloads deeply and has little or no application awareness.
- Why it is used:
  - Enforce basic network segmentation and perimeter security (e.g., only allow TCP 80/443 out, block everything else).​
  - Reduce attack surface by limiting reachable ports and services.

- Where it is used:
  - Internet edge of an organization (between internal LAN and the internet).
  - Between internal network segments (e.g., user VLAN ↔ server VLAN, OT network ↔ IT network).
 
- Working mechanism (high level):
  - Operates mainly at OSI Layers 3–4 (network and transport).
  - For each packet or connection, checks rules like: source IP, destination IP, protocol (TCP/UDP), source port, destination port, and connection state (NEW/ESTABLISHED).
  - If a rule matches, it allows or denies; it does not usually inspect HTTP headers, SQL queries, or JSON payloads.
 
  ## 2. Next-generation firewall (NGFW)

  - NGFW is an evolved firewall that combines traditional firewall features with deep packet inspection, intrusion prevention (IDS/IPS), application awareness/control, and often user-identity awareness. It can inspect traffic up to Layer 7 and recognize applications (e.g., Facebook, SSH, DNS-over-HTTPS) regardless of port.​
  - Why it is used:
    - Detect and block modern threats such as malware, ransomware, and exploits using DPI and IPS signatures.​
    - Enforce policies based on user identity and specific applications, not just IP/port (e.g., “allow only HR group to use SSH,” “block BitTorrent”).
    - Consolidate multiple security functions (firewall, VPN, IPS, URL filtering, antivirus) in one device.

  - Where it is used:
    - Enterprise perimeter (internet edge) as the primary gateway firewall.
    - Between internal segments with stronger inspection requirements (e.g., user network ↔ data center).​
   
  - Working mechanism:
    - Still enforces traditional L3/L4 rules, but also performs deep packet inspection into the payload.
    - Uses:
      - Application identification: analyzes headers, patterns, and payload to label traffic as a specific app, even if it uses non-standard ports or tunnels over HTTPS.
      - IPS engine: compares traffic against signatures and behavioral rules to detect exploits, port scans, and known attack patterns.
      - URL filtering and sometimes malware scanning using threat intelligence feeds and reputation.

    - Policies can be written like “User group X can use app Y to destination Z,” not just “allow TCP 443.”
   
  
