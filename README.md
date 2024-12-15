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

- **Dependency Management:**
  - Utilizes `pipenv` for managing Python dependencies.

- **Containerization:**
  - Dockerized application for easy deployment and scalability.

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
  - Docker
  - Docker Compose (optional)
  - `pipenv`

### Setup Steps

#### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/intrusion-detection.git
cd intrusion-detection
```

2. **Install Dependencies**
```
sudo apt-get update
sudo pip3 install pipenv
```
Initialize pipenv and install dependencies:
```
pipenv install
```

3. **Build Docker Image**
```
docker build -t pids .
```

4. **Run Docker Container**
```
sudo docker run --rm -it \
    --net=host \
    --cap-add=NET_ADMIN \
    --cap-add=NET_RAW \
    --name raspberry-pi-ids \
    raspberry-pi-ids
```
**Explaination**
        --net=host: Shares the host's network stack, allowing the container to access network interfaces directly.
        --cap-add=NET_ADMIN and --cap-add=NET_RAW: Grants the container the necessary capabilities to capture packets.
        --rm: Automatically removes the container when it exits.
        -it: Runs the container in interactive mode with a pseudo-TTY.

Verify the container is running:
```
sudo docker ps
```
5. **Set Up as a systemd Service**
To run the IDS as a background service using Docker:
    1.  Create Service File:
    ```
    sudo nano /etc/systemd/system/ids.service
    ```
    2. Add the following configuration:
    ```
    [Unit]
    Description=Intrusion Detection System
    After=network.target

    [Service]
    ExecStart=/usr/bin/docker-compose up
    WorkingDirectory=/home/pi/intrusion-detection/
    Restart=always
    User=pi  # Replace with your username

    [Install]
    WantedBy=multi-user.target
    ```
    4.  Enable/ start service
    ```
    sudo systemctl daemon-reload
    sudo systemctl enable ids.service
    sudo systemctl start ids.service
    ```
    5. Check Service Status
    ```
    sudo systemctl status ids.service
    ```
6. **Configuring Multiple Interfaces**
When adding a Wi-Fi card with monitor mode support:

Update utils/config.py:
```
INTERFACES = ["eth0", "wlan1"]  # Add your monitor mode Wi-Fi interface
```
Rebuild and Restart the Docker Container:
```docker-compose down
docker-compose up -d --build
```

## Usage

**View real-time logs**
``` 
sudo docker logs -f pids
```
**Stop pids**
```
sudo systemctl stop ids.service
```

