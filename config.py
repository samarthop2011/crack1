import os
from dotenv import load_dotenv
load_dotenv()

DISCORD_TOKEN = os.getenv("DISCORD_TOKEN", "")
CHANNEL_ID    = int(os.getenv("CHANNEL_ID", "0") or 0)
PREFIX        = os.getenv("PREFIX", "!")

DORK = os.getenv(
    "DORK",
    'ssl.cert.issuer.cn="megarac.com" && app="lighttpd" && country!="CN" && port="443"',
)

# scan like hell
DISCOVERY_WORKERS  = int(os.getenv("DISCOVERY_WORKERS", "60"))
VERIFY_CONCURRENCY = int(os.getenv("VERIFY_CONCURRENCY", "1000"))
CVE_CONCURRENCY    = int(os.getenv("CVE_CONCURRENCY", "300"))
TLS_TIMEOUT  = float(os.getenv("TLS_TIMEOUT", "5"))
HTTP_TIMEOUT = float(os.getenv("HTTP_TIMEOUT", "7"))

EXPAND           = os.getenv("EXPAND", "1") == "1"      # /24 sweep around hits
CYCLE_SLEEP      = int(os.getenv("CYCLE_SLEEP", "20"))  # secs between full cycles
RECHECK_EVERY    = int(os.getenv("RECHECK_EVERY", "6")) # re-verify known vulns every N cycles
ANNOUNCE_CONFIRMED = os.getenv("ANNOUNCE_CONFIRMED", "1") == "1"
PING = os.getenv("PING", "@here")

SEEN_FILE = "seen_ips.json"
VULN_FILE = "vulnerable.json"
