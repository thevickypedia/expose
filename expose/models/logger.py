"""Custom logging setup shared across modules."""

import logging

LOGGER = logging.getLogger(__name__)
formatter = logging.Formatter(
    fmt='%(asctime)s - %(levelname)s - [%(module)s:%(lineno)d] - %(funcName)s - %(message)s',
    datefmt='%b-%d-%Y %I:%M:%S %p'
)
handler = logging.StreamHandler()
handler.setFormatter(fmt=formatter)
LOGGER.addHandler(hdlr=handler)
LOGGER.setLevel(level=logging.DEBUG)
