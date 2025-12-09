"""
Configuration constants for ACI Tool.
"""

# -------------------------------------------------------
# API Endpoints
# -------------------------------------------------------

API_NODE_CLASS = "/api/node/class"
API_CLASS = "/api/class"


# -------------------------------------------------------
# Network Filtering
# -------------------------------------------------------

# Excluded Networks (for filtering common/private ranges)
EXCLUDED_CIDRS = {
    "0.0.0.0/0",
    "10.0.0.0/8",
    "192.168.0.0/16",
    "172.16.0.0/12"
}


# -------------------------------------------------------
# HTTP Configuration
# -------------------------------------------------------

# Retry configuration for HTTP requests
RETRY_TOTAL = 3
RETRY_BACKOFF_FACTOR = 1
RETRY_STATUS_FORCELIST = [429, 500, 502, 503, 504]
RETRY_ALLOWED_METHODS = ["HEAD", "GET", "OPTIONS", "POST"]


# -------------------------------------------------------
# Cache Configuration
# -------------------------------------------------------

# Maximum size for LRU caches
API_CACHE_SIZE = 64
NODE_INVENTORY_CACHE_SIZE = 1
