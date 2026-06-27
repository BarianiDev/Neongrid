import os

FEED_PATH = os.path.join(os.path.dirname(__file__), "threat_feed.txt")

def load_knowbn_bad_ips():
    """Loads the set of known malicious IPs from the local threat feed."""
    if not os.path.exists(FEED_PATH):
        return set()
    with open(FEED_PATH) as f:
        return {
            line.strip()
            for line in f
            if line.strip() and not line.startswith("#")
        }