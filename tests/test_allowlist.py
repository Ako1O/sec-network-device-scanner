from sec_network_device_scanner.allowlist import normalize_mac


def test_normalize_mac():
    assert normalize_mac("aa-bb-cc-11-22-33") == "AA:BB:CC:11:22:33"
    assert normalize_mac(" AA:BB:CC:11:22:33 ") == "AA:BB:CC:11:22:33"
