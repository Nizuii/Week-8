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
