# What is Remcos RAT?

Remcos RAT (Remote Control and Surveillance) is a type of malware known as a **Remote Access Trojan**. It allows an attacker to remotely control and monitor an infected computer, primarily targeting systems running Microsoft Windows.

Originally created as a legitimate remote administration tool, Remcos has since been widely abused by cybercriminals to hijack systems for malicious purposes such as data theft, persistence, and further malware deployment.

---

## Remcos RAT Infection Mechanism

### 1. Initial Delivery
Attackers commonly deliver Remcos using:

- Phishing emails  
- Office documents that require macros to be enabled  
- PDFs claiming you need an “update”  
- Cracked or pirated executable files  

### 2. Execution of the Downloader
Once the victim opens the malicious file, a downloader is executed. Common methods include:

- **GuLoader**  
  A small, heavily obfuscated downloader widely known for distributing Remcos.

- **VBA Macros or HTA Scripts**  
  The document may show a fake prompt such as:  

  ```bash
  Enable content to view the document properly!

- **Powershell downloader**  
   A hidden powershell command retrieves the payload from a remote server. This stage is quiet, quick & sneaky.

### 3. Decryption & Drop of Remcos Payload.
Remcos rarely arrives in plain form. its almost always:
- Encrypted
- Packed
- Obfuscated
- Hidden in alternate data streams

### 4. Persistance
Remcos wants to survive restarts so it sets persistance through:
- Registry key runs
- Scheduled tasks  
  Runs every startup on every few minutes/
- Windows services

### 5. Establishing connection with C2 server
Remcos reaches out the attackers command & control(C2)
- Over TCP
- Uusally on uncommon ports
- Sometimes encrypted or obfuscated traffic.
It sends back:
- OS version
- IP/Geolocation
- Running processes
- Usernames
- Installed software
This registers victims device into the attackers dashboard.

### 6. Full Remote Control Activated.
Once fully connected the attacker can:
- Steal passwords
- Capture keystrokes
- Turn on webcam
- Move/Steal/Delete file
