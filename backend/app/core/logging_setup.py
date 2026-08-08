import logging

from .logging_filter import SecretScrubber

# Set up logging with secret scrubbing.
# Runs at import time by design: root-handler mutation must stay import-time
# so every module's getLogger() call observes the configured root logger.
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
scrubber = SecretScrubber()
for handler in logging.root.handlers[:]:
    logging.root.removeHandler(handler)
handler = logging.StreamHandler()
handler.setFormatter(formatter)
handler.addFilter(scrubber)
logging.root.addHandler(handler)
logging.root.setLevel(logging.INFO)
