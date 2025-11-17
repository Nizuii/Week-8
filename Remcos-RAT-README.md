# Fileless Remcos Remote Access Trojan (May 2025)
<ul>
  <li>A malicious campaign was spotted in May 2025 that uses a stealthy strain of the Remcos RAT (Remote Access Trojan).</li>
  <li>It’s fileless. That means the attacker tries to avoid writing malicious files to disk; instead they use Windows built-in tools to load and run the malware in memory.</li>
  <li>Attackers delivered it via a combination of: a ZIP file (attached to a phishing email) → a Windows Shortcut file (.LNK) → a Windows HTA (HTML application) → an obfuscated PowerShell script.</li>
</ul>

<h2>How the attack chain works</h2>
<ol>
  <li><strong>Phishing Email</strong></li>
  <ul>
    <li>The victim receives an email themed around taxes (to trick them into trusting it). The email has a ZIP attachment.</li>
    <li>Inside the ZIP: a .lnk (shortcut) file.</li>
  </ul>
  <li><strong>LNK file & trusted tool misuse</strong></li>
  <ul>
    <li>When the user opens the .lnk, it invokes mshta.exe (a built-in Windows tool for running HTA files). This is “living-off-the-land” — using what’s already on the system to avoid detection.</li>
    <li>mshta.exe loads a remote HTA file (for example, xlab22.hta).</li>
  </ul>
  <li><strong>Script & memory execution</strong></li>
  <ul>
    <li>The HTA triggers a PowerShell script (here named 24.ps1), which is heavily obfuscated. It uses shellcode to allocate memory (VirtualAlloc), make API calls dynamically, and inject the Remcos code into memory — so nothing (or very little) touches the disk.</li>
    <li>Because it runs in memory and uses legitimate Windows binaries, standard file-based antivirus may miss it.</li>
  </ul>
  <li><strong>Control & persistence</strong></li>\
  <ul>
    <li>Once in memory, Remcos sets up command-and-control (C2) communication: encrypted traffic to a remote server (over TLS) to receive commands, exfiltrate data.</li>
    <li>It sets up persistence (so it survives reboots) via registry “Run” keys. It also uses a mutex (identifier) to avoid reinfection.</li>
    <li>It includes anti-analysis/sandbox checks: if it senses it’s being “watched” (via virtualised environment), it may stop execution to avoid detection.</li>
  </ul>
</ol>
