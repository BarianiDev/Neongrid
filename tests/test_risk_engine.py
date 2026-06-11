from Neongrid.analyzer.risk_engine import analyze_port

def test_known_port_ftp():
    result = analyze_port(21)
    assert result["risk"] == "HIGH"

def test_known_port_https():
    result = analyze_port(443)
    assert result["risk"] == "LOW"

def test_unknown_port():
    result = analyze_port(9999)
    assert result["risk"] == "UNKNOWN"