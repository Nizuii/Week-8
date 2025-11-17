# What is Remcos RAT?
Remcos RAT (Remote Control and Surveillance) is a widely recongnised remote access trojan that allow attackers to take full control of windows system, exfiltrate sensitive data, and manipulate 
infected machines remotely. Originally developed and marketed by a company called Breaking Security as a legitimate remote administration tool, Remcos has since been widely abused for malicious 
purposes by cybercriminals.

<h2>Infection Mechanism:</h2>
<ol>
  <li>Attackers send phishing emails containing Microsoft Office documents (usually XLS or DOC), password-protected ZIP files, or shortcut files (LNK) that look like routine communications such as remittance notifications or invoices.</li>
  <li>If the user opens the attachment and enables macros or scripting, the embedded code executes a sequence of scripts (often PowerShell or VBS) on the victim's machine.</li>
  <li>These scripts download additional payloads from the attacker-controlled server, which may include obfuscated files or wrappers (like AutoIt or .NET DLLs) to evade security detection and analysis.</li>
  <li>The loader extracts and decrypts the Remcos RAT binary and injects it into a legitimate process on the system (often using “process hollowing” techniques—injecting code into processes like RegAsm.exe).</li>
  <li>Remcos then decrypts its configuration block, sets up persistence by modifying the registry or creating scheduled tasks, and establishes encrypted communication (using protocols like RC4 or AES over TLS) with its C2 server.</li>
  <li>The RAT sends system information to the attacker and waits for further commands, enabling complete remote control, privilege escalation, and data theft while maintaining stealth to avoid user suspicion or security product detection.</li>
</ol>
