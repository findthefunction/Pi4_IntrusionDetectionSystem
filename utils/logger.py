import logging
import os

class Logger:
    """
    Logger class to handle logging of IDS alerts and events.
    Logs are written to both a file and the console with timestamps and severity levels.
    """

    def __init__(self, log_file="logs/intrusion_log.txt"):
        """
        Initializes the Logger.

        Args:
            log_file (str): Path to the log file.
        """
        # Ensure the logs directory exists
        log_dir = os.path.dirname(log_file)
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)

        # Create a logger object
        self.logger = logging.getLogger("IDS_Logger")
        self.logger.setLevel(logging.INFO)

        # Create a file handler for logging to a file
        fh = logging.FileHandler(log_file)
        fh.setLevel(logging.INFO)

        # Create a console handler for logging to the console
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)

        # Define a formatter that includes the timestamp and log level
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        fh.setFormatter(formatter)
        ch.setFormatter(formatter)

        # Add handlers to the logger
        self.logger.addHandler(fh)
        self.logger.addHandler(ch)

    def log(self, message, level="INFO"):
        """
        Logs a message with the specified severity level.

        Args:
            message (str): The message to log.
            level (str): The severity level ('INFO', 'WARNING', 'ERROR', 'DEBUG').
        """
        if level.upper() == "INFO":
            self.logger.info(message)
        elif level.upper() == "WARNING":
            self.logger.warning(message)
        elif level.upper() == "ERROR":
            self.logger.error(message)
        elif level.upper() == "DEBUG":
            self.logger.debug(message)
        else:
            self.logger.info(message)
