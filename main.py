from capture.packet_sniffer import PacketSniffer
from detection.heuristic_detector import HeuristicDetector
from utils.logger import Logger
from utils import config

def packet_callback(packet_info):
    detector.analyze(packet_info)

if __name__ == "__main__":
    logger = Logger(log_file=config.LOG_FILE)
    detector = HeuristicDetector(packet_threshold=config.PACKET_THRESHOLD, 
                                 interval=config.INTERVAL, 
                                 logger=logger)

    sniffer = PacketSniffer(interface=config.INTERFACE, callback=packet_callback)
    sniffer.start()
