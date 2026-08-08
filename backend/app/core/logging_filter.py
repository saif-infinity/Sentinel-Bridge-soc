import logging
import re

class SecretScrubber(logging.Filter):
    def filter(self, record):
        if hasattr(record, 'msg') and isinstance(record.msg, str):
            # Pattern to match common secret keys and their values
            patterns = [
                r'(?i)(password|pass|secret|key|token)[:=]\s*\S+',
                r'(?i)(authorization)[:=]\s*\S+',
                r'(?i)(api_key)[:=]\s*\S+',
            ]
            for pattern in patterns:
                record.msg = re.sub(pattern, lambda m: m.group(0).split('=')[0] + '=***', record.msg)
        return True