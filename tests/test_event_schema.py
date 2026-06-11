from Neongrid.normalizer.event_schema import build_event

def test_event_has_required_fields():
    event = build_event("port_scan_result", {"port": 22, "service": "SSH"})
    assert "timestamp" in event
    assert "event_type" in event
    assert event["source"] == "Neongrid"

def test_event_has_correct_type():
    event = build_event("test_event", {})
    assert event["event_type"] == "test_event"

def test_data_is_marged():
    event = build_event("port_scan_result", {"port": 80})
    assert event["port"] == 80