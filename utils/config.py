# Network Interface Configuration
INTERFACES = ["eth0"]  # List of interfaces to monitor (e.g., ["eth0", "wlan1"])

# Logging Configuration
LOG_FILE = "logs/intrusion_log.txt"

# Heuristic Detector Configuration
PACKET_THRESHOLD = 100   # Maximum packets per interval from a single IP
INTERVAL = 60            # Time interval in seconds for packet threshold
PORT_SCAN_THRESHOLD = 20 # Maximum unique ports scanned by a single IP within scan interval
SCAN_INTERVAL = 60       # Time interval in seconds for port scan detection

# Packet Filter Configuration
BPF_FILTER = "tcp or udp"  # Berkeley Packet Filter string to filter captured packets


# (Future) Wireless Interface Configuration
# WIRELESS_INTERFACE = "wlan0"  # To be used when a monitor mode card is added