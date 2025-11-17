# What is a fire wall?
A firewall is a network security system that monitors and controls incoming and outgoing network traffic based on predetermined security rules. It acts as a barrier between a trusted internal network (like a home or office) and an untrusted external network (like the internet) to protect against unauthorized access and threats. Firewalls can be hardware, software, or a combination of both, and they allow safe traffic while blocking malicious data.
# Types of firewall
<h2>Traditional firewall</h2>
<ul>
  <li>They guard the network perimeter by checking basic traffic details.</li>
</ul>
<h2>What they look at:</h2>
<ul>
  <li>Source IP</li>
  <li>Destination IP</li>
  <li>Source port</li>
  <li>Destination port</li>
  <li>Protocol (TCP, UDP, ICMP)</li>
  <li>Stateful ones track connections (is this packet part of an existing session?)</li>
</ul>
<h2>How it works internally:</h2>
<ol>
  <li>Packet arrives</li>
  <li>Firewall checks IP header</li>
  <li>Checks port numbers</li>
  <li>Applies a simple ruleset: ALLOW or DENY</li>
  <li>For stateful firewalls:</li>
</ol>
