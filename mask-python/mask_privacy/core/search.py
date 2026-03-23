import logging
import hmac
import hashlib
from typing import Literal, Union

logger = logging.getLogger("mask.search")

class BucketManager:
    """Manages bucket-based indexing for secure range queries.
    """

    @staticmethod
    def date_bucket(date_str: str, granularity: Literal['year', 'month', 'day'] = 'month') -> str:
        """Create a bucket for a date string (YYYY-MM-DD)."""
        import re
        parts = re.split(r'[-/]', date_str)
        if not parts:
            return "invalid_date"
        
        year = parts[0]
        month = parts[1] if len(parts) > 1 else "01"
        day = parts[2] if len(parts) > 2 else "01"

        if granularity == 'year':
            return f"date:y:{year}"
        elif granularity == 'day':
            return f"date:d:{year}-{month}-{day}"
        else:
            return f"date:m:{year}-{month}"

    @staticmethod
    def numeric_bucket(value: Union[int, float, str], size: int = 10) -> str:
        """Create a bucket for a numeric value."""
        try:
            val = float(value)
        except (ValueError, TypeError):
            return "invalid_num"
        
        floor = int(val // size) * size
        return f"num:{size}:{floor}"

    @staticmethod
    def get_bucket_index(bucket_val: str) -> str:
        """Generate a secure blind index for a bucket value."""
        from mask_privacy.core.crypto import get_crypto_engine
        secret = get_crypto_engine().get_index_secret()
        return hmac.new(secret, bucket_val.encode("utf-8"), hashlib.sha256).hexdigest()
