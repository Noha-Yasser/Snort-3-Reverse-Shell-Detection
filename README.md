# Snort-3-Reverse-Shell-Detection
This project focuses on detecting suspicious reverse shell activity using Snort 3 in a controlled virtual lab environment.  The main goal was not only to generate an alert, but to understand how a SOC Analyst can design a focused network detection that provides meaningful and actionable security information.

## Lab Environment

- Kali Linux – Attacker / IDS Sensor
- Windows 10 – Target
- Snort 3.12.2.0
- TCP-based network communication
- Custom Snort detection rule
- Isolated virtual lab environment

## Detection Approach

The detection was designed around several key concepts:

### 1. Traffic Direction

The rule specifies the expected traffic direction between the external and internal networks.

This helps Snort focus on relevant traffic instead of inspecting unrelated connections.

### 2. TCP Session State

The rule uses:

`flow:to_server,established`

This limits inspection to established TCP sessions and avoids triggering on initial connection packets such as SYN/ACK traffic.

### 3. Content Matching

The rule uses a specific content indicator:

`content:"whoami"`

This provides a focused detection anchor based on the command executed during the controlled test.

### 4. Reducing False Positives

A detection rule should not simply generate as many alerts as possible.

Using multiple conditions such as protocol, destination port, traffic direction, session state, and specific content helps increase detection precision and reduce unnecessary alerts.

## Custom Rule

```snort
alert tcp $EXTERNAL_NET any -> $HOME_NET 4444 (
    msg:"HW3 - LIVE Shell Detected";
    flow:to_server,established;
    content:"whoami";
    sid:1000010;
    rev:1;
)
