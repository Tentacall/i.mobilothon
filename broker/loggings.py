import coloredlogs
import logging

# Initialize the logger
logger = logging.getLogger(__name__)

# Set the log level (e.g., DEBUG, INFO, WARNING, ERROR, CRITICAL)
logger.setLevel(logging.DEBUG)

# Initialize coloredlogs
coloredlogs.install(level='DEBUG', logger=logger)

# Now you can use the logger to log messages with color
if __name__ == '__main__':
    logger.debug('This is a debug message')
    logger.info('This is an info message')
    logger.warning('This is a warning message')
    logger.error('This is an error message')
    logger.critical('This is a critical message')
