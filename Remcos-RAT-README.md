# What is Remcos RAT?
<ul>
  <li>Remcos RAT (Remote Control and Survceillance) is a type of malware known as remote access trojan that allows attacker to remote control and monitor infected computers, mainly targetting systems running microsoft windows.</li>
  <li>Remcos RAT was a tool originally developed as a legitimate remote administration software but has become widely used by cyber criminals to hijack computers, often for malicious purpose.</li>
</ul>

## Remcos RAT Infection Mechanism.
<ol>
  <li><h3>Initial Delivery</h3></li>
  <ul>
    <li>A phishing email</li>
    <li>An office document requiring macro enabled</li>
    <li>A PDF pretending to need an update.</li>
    <li>Cracked exe software.</li>
  </ul>
  <li><h3>Execution of downloader</h3></li>
  <ul>
    <li><strong>GuLoader</strong></li>
    A tiny obfuscated downloader known for delivering Remcos.
    <li><strong>VBA Macros or HTA Scripts</strong></li>
    The document pop's up a fake message like:
    ```bash
    Enable content to view the document properly!
    ```
  </ul>
</ol>
