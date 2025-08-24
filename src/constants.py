# App Info
APP_NAME = "EncryptoPack"
CURRENT_VERSION = "v2.1"

# Format Identification
FILE_HEADER = b"PV2"
PASS_TEXT   = b"EPV2FILE"
EOF_MARKER  = b"EOF"

# File Extensions
CURRENT_EXT       = ".pv2"
IV_KEY_EXT        = ".ivkey"
RECOVERY_KEY_EXT  = ".rkey"
TEMP_EXT          = ".temp"
MARKER_FILE       = "~pv2_packed"
MARKER_FILE_TEXT  = "~pv2 Marker"
EXTRACTION_SUFFIX = "_out"

# File header info for future compatability
FILE_HEADERS_HISTORY = [
    {"HEADER": b"PV2", "VERSION": "v2.0"}
]

