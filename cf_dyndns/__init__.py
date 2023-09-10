import logging
import sys

root_logger = logging.getLogger()

sh = logging.StreamHandler(stream=sys.stdout)
formatter = logging.Formatter("(%(levelname)s) %(asctime)s - %(module)s - %(message)s")
sh.setFormatter(formatter)
root_logger.addHandler(sh)
root_logger.setLevel(logging.INFO)
