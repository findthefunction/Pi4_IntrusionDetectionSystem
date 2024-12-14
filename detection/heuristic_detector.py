import time
from .base_detector import BaseDetector

class HeuristicDetector(BaseDetector):
    def __init__(self, packet_threshold=100, interval=60, logger=None):
        super().__init__(logger=logger)
        self.packet_counts = {}
        self.packet_threshold = packet_threshold
        self.interval = interval
        self.last_reset = time.time()

    def analyze(self, packet_info):
        current_time = time.time()
        if current_time - self.last_reset > self.interval:
            self.packet_counts.clear()
            self.last_reset = current_time

        src = packet_info['src_ip']
        if src:
            self.packet_counts[src] = self.packet_counts.get(src, 0) + 1
            if self.packet_counts[src] > self.packet_threshold:
                alert = f"High packet rate detected from {src}"
                self.logger.log(alert)
