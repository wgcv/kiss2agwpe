# kiss2agwpe

A lightweight Python bridge that translates between KISS TNCs and the AGWPE protocol.

This allows software that expects an AGWPE-compatible packet engine to work with KISS devices, making it possible to use applications such as PAT Winlink on macOS without requiring a native AX.25 stack.

## Usage:
    `python3 kiss2agwpe.py [--kiss-host HOST] [--kiss-port PORT] [--agwpe-port PORT] [--debug]`
 
## Features
KISS-to-AGWPE protocol translation
Compatible with serial and TCP KISS TNCs
Works with PAT Winlink and other AGWPE-capable software
No kernel AX.25 support required
Cross-platform Python implementation
Designed for macOS packet radio operation

## Typical Use Case
```
PAT Winlink
      │
      ▼
 AGWPE Client
      │
      ▼
  kiss2agwpe
      │
      ▼
   KISS TNC
      │
      ▼
    Radio
```

## Why?

Many packet radio applications support AGWPE but do not communicate directly with KISS TNCs. On macOS, the lack of native AX.25 support can make packet radio applications difficult to use. kiss2agwpe fills this gap by presenting an AGWPE-compatible interface while communicating with a standard KISS TNC. AGWPE-based software relies on a TCP protocol that abstracts TNC communication, while KISS devices provide a simple modem-style interface.

## Use Cases
- PAT Winlink on macOS
- Packet radio experimentation
- Connecting modern KISS TNCs to AGWPE-based software
- Development and testing of packet radio applications

  
