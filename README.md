# Pi4_IntrusionDetectionSystem
# Raspberry Pi Intrusion Detection System (IDS)

## Overview

This project is a foundational Intrusion Detection System (IDS) designed to run on a Raspberry Pi with Kali Linux. It monitors network traffic to identify anomalies and potential security threats. Initially configured to monitor traffic via the Ethernet interface, the system is designed for future upgrades to include comprehensive wireless traffic monitoring.

## Features

- **Packet Capture:**
  - Monitors Ethernet traffic using Scapy.
  - Future support for wireless traffic via a monitor mode-enabled Wi-Fi card.

- **Heuristic Detection:**
  - High packet rate detection.
  - Port scan detection.
  - Unusual protocol usage detection.
  - Large packet size detection.

- **Logging:**
  - Logs alerts to both a file and the console with timestamps and severity levels.

- **Modular Design:**
  - Easily extendable with additional detection modules.
  - Supports multiple network interfaces.

- **Service Integration:**
  - Runs as a `systemd` service for continuous monitoring.

## Installation

### Prerequisites

- **Hardware:**
  - Raspberry Pi 4 (or compatible)
  - Kali Linux installed
  - Ethernet connection to a wireless router

- **Software:**
  - Python 3.x

### Setup Steps

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/findthefunction/intrusion-detection.git
   cd intrusion-detection

2. **Install Dependencies**
```
sudo apt-get update
sudo apt-get install python3-pip libpcap-dev
sudo pip3 install -r requirements.txt
```