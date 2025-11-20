# What is Remcos RAT?
<ul>
  <li>Remcos RAT (Remote Control and Survceillance) is a type of malware known as remote access trojan that allows attacker to remote control and monitor infected computers, mainly targetting systems running microsoft windows.</li>
  <li>Remcos RAT was a tool originally developed as a legitimate remote administration software but has become widely used by cyber criminals to hijack computers, often for malicious purpose.</li>
</ul>

## How Remcos RAT infects a windows system.
<ul>
  <li>Attackers send phishing emails that commonly carry a ZIP archieve or icrosoft office document as an attachment.</li>
  <li>ZIP files may contain deceptive shortcuts (LNK files) or documents with macros. Opening these files executes a hidden script or macro which starts the infection process.</li>
  <li>These scripts (often PowerShell) download and run the actual remcos executable on the PC</li>
  <li>Remcos uses techniques like process injection or process hollowing, allowing it to run inside trusted Windows processes, making detection much harder.</li>
  <li>The malware manipulates Windows settings (for example, bypassing User Account Control by editing registry values) to gain persistence and higher privileges.</li>
  <li>It ensures it launches automatically on every startup by making changes to the Windows Registry (such as adding entries under HKCU\Software\Microsoft\Windows\CurrentVersion\Run).</li>
  <li>After infection, Remcos connects to its command and control (C2) server to receive commands from attackers and begin surveillance or further attacks on the compromised system.</li>
</ul>
