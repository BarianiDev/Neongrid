RISK_PROFILES = {

    21: {
        "risk": "HIGH",
        "description": "FTP may expose credentials in plaintext"
    },

    22: {
        "risk": "MEDIUM",
        "description": "SSH exposed for remote access"
    },

    23: {
        "risk": "CRITICAL",
        "description": "Telnet is an insecure protocol and should not be exposed"
    },

    80:{
        "risk": "LOW",
        "description": "HTTP service exposed"
    },

    443: {
        "risk": "LOW",
        "description": "HTTPS service exposed"
    },

    3306: {
        "risk": "HIGH",
        "description": "MySQL database exposed"
    }
}


def analyze_port(port):
    return RISK_PROFILES.get(
        port, 
        {
            "risk": "UNKNOWN",
              "description": "No information available"
              }
        )