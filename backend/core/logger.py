import logging
from pathlib import Path

from backend.core.config import settings


class CyberSentinelLogger:
    """
    Central logging system for Cyber Sentinel X.
    """

    def __init__(self):
        settings.LOG_DIR.mkdir(
            parents=True,
            exist_ok=True
        )

        self.logger = logging.getLogger(
            "cyber_sentinel_x"
        )

        self.logger.setLevel(
            getattr(
                logging,
                settings.LOG_LEVEL.upper(),
                logging.INFO
            )
        )

        self.logger.propagate = False

        if not self.logger.handlers:
            self._configure_handlers()

    def _configure_handlers(self):

        formatter = logging.Formatter(
            "%(asctime)s | "
            "%(levelname)s | "
            "%(name)s | "
            "%(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )

        file_handler = logging.FileHandler(
            settings.LOG_FILE
        )

        file_handler.setLevel(
            logging.INFO
        )

        file_handler.setFormatter(
            formatter
        )

        console_handler = logging.StreamHandler()

        console_handler.setLevel(
            logging.INFO
        )

        console_handler.setFormatter(
            formatter
        )

        self.logger.addHandler(
            file_handler
        )

        self.logger.addHandler(
            console_handler
        )

    def info(self, message):
        self.logger.info(message)

    def warning(self, message):
        self.logger.warning(message)

    def error(self, message):
        self.logger.error(message)

    def critical(self, message):
        self.logger.critical(message)

    def debug(self, message):
        self.logger.debug(message)

    def exception(self, message):
        self.logger.exception(message)


logger = CyberSentinelLogger()


if __name__ == "__main__":

    print("=" * 60)
    print("CYBER SENTINEL X - LOGGER")
    print("=" * 60)

    logger.info(
        "Cyber Sentinel X logging system initialized"
    )

    logger.warning(
        "Logger warning test"
    )

    logger.error(
        "Logger error test"
    )

    print(f"Log file: {Path(settings.LOG_FILE)}")
    print("Logger   : READY")
