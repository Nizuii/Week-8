# STUNXNET
- Worlds first cyber weapon that caused real world physical destruction.
- It was developed by nation-states (US & Israel).
- It targeted Iran's nuclear program around 2009-2010 and destroyed uranium centrifuges.

## Infection mechanism.
### 1. Delivery Mechanism.
- It spread using:
  
  - USB Drives
  - Windows zero days.
  - Network shares.
  - LNK exploit.

### 2. Propadation Mechanism.

- Once insid3 it moved laterally like a ghost.
  - No crashing system.
  - No raising alarm.
  - Only looking for one specific target: **Siemens Industrial Controller**
 
### 3. Targeting System

- It looked for:
  - Siemens step7 controller.
  - Centrifuge control logic
  - Very specific frequency pattern
  - Very specific hardware layout
 
### 4. Payload

- It altered the retention speed of nuclear centrifuges.
- The malware made them spin:
  - Too fast
  - Too slow
  - In cycles that caused metal fatigue.

And while doing this, it fed fake normal readings to the control room.

### 5. Stalth & Persistance.

- Hid its files
- Replace legitimate drivers with malicious signed ones.
- Avoided detection by cyber security tools.
- Erased itself often a timer expired.
