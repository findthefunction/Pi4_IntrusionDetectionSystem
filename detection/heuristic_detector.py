import time
from collections import defaultdict
from .base_detector import BaseDetector

class HeuristicDetector(BaseDetector):
    """
    HeuristicDetector implements rule-based methods to detect potential intrusions
    such as high packet rates, port scans, unusual protocol usage, and large packets.
    """

    def __init__(self, packet_threshold=100, interval=60, port_scan_threshold=20, scan_interval=60, logger=None):
        """
        Initializes the HeuristicDetector with thresholds and intervals.

        Args:
            packet_threshold (int): Maximum packets allowed per interval from a single IP.
            interval (int): Time interval in seconds for packet rate detection.
            port_scan_threshold (int): Maximum unique ports scanned by a single IP within scan interval.
            scan_interval (int): Time interval in seconds for port scan detection.
            logger (Logger): Instance of the Logger class for logging alerts.
        """
        super().__init__(logger=logger)
        self.packet_counts = {}  # Tracks packet counts per source IP
        self.packet_threshold = packet_threshold
        self.interval = interval
        self.port_scan_counts = defaultdict(lambda: defaultdict(int))  # Tracks port scans per source IP
        self.port_scan_threshold = port_scan_threshold
        self.scan_interval = scan_interval
        self.last_reset = time.time()
        self.last_scan_reset = time.time()

    def analyze(self, packet_info):
        """
        Analyzes packet information to detect anomalies based on predefined heuristics.

        Args:
            packet_info (dict): Dictionary containing packet metadata.
        """
        current_time = time.time()

        # Reset packet counts periodically based on the defined interval
        if current_time - self.last_reset > self.interval:
            self.packet_counts.clear()
            self.last_reset = current_time

        # Reset port scan counts periodically based on the scan interval
        if current_time - self.last_scan_reset > self.scan_interval:
            self.port_scan_counts.clear()
            self.last_scan_reset = current_time

        # Packet Rate Detection: Check if a single IP exceeds the packet threshold
        src = packet_info.get('src_ip')
        if src:
            self.packet_counts[src] = self.packet_counts.get(src, 0) + 1
            if self.packet_counts[src] > self.packet_threshold:
                alert = (f"High packet rate detected from {src} "
                         f"({self.packet_counts[src]} packets in {self.interval} seconds)")
                self.logger.log(alert, level="WARNING")

        # Port Scan Detection: Check if a single IP scans multiple unique ports
        if src and 'dst_port' in packet_info:
            dst_port = packet_info['dst_port']
            self.port_scan_counts[src][dst_port] += 1
            unique_ports = len(self.port_scan_counts[src])
            if unique_ports > self.port_scan_threshold:
                alert = (f"Potential port scan detected from {src} "
                         f"(scanned {unique_ports} unique ports in {self.scan_interval} seconds)")
                self.logger.log(alert, level="WARNING")

        # Unusual Protocol Detection: Flag unexpected protocols
        proto = packet_info.get('proto')
        expected_protocols = [6, 17, 1]  # TCP, UDP, ICMP protocol numbers
        if proto and proto not in expected_protocols:
            alert = f"Unusual protocol detected: {proto} from {src}"
            self.logger.log(alert, level="WARNING")

        # Large Packet Detection: Flag packets exceeding the size threshold
        packet_length = packet_info.get('length', 0)
        LARGE_PACKET_THRESHOLD = 1500  # Bytes, typical MTU is 1500
        if packet_length > LARGE_PACKET_THRESHOLD:
            alert = (f"Large packet detected from {src} "
                     f"(Size: {packet_length} bytes)")
            self.logger.log(alert, level="WARNING")
