import logging


def initialize(log_name, file_name):
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    handler = logging.FileHandler(file_name)
    handler.setFormatter(formatter)
    logger = logging.getLogger(log_name)
    logger.setLevel(logging.DEBUG)
    logger.addHandler(handler)
    return logger
