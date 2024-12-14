import datetime
import logging

class Logger:
    def __init__(self, log_file="intrusion_log.txt"):
        self.logger = logging.getLogger("IDS_Logger")
        self.logger.setLevel(logging.INFO)

        # File Handler
        fh = logging.FileHandler(log_file)
        fh.setLevel(logging.INFO)

        # Console Handler
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)

        # Formatter
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        fh.setFormatter(formatter)
        ch.setFormatter(formatter)

        # Add Handlers
        self.logger.addHandler(fh)
        self.logger.addHandler(ch)

    def log(self, message, level="INFO"):
        if level == "INFO":
            self.logger.info(message)
        elif level == "WARNING":
            self.logger.warning(message)
        elif level == "ERROR":
            self.logger.error(message)
        elif level == "DEBUG":
            self.logger.debug(message)
        else:
            self.logger.info(message)
