from sec_network_device_scanner.oui import OUILookup


def test_oui_lookup_does_not_crash():
    oui = OUILookup()
    # Example MAC format; manufacturer may be None depending on DB version
    _ = oui.manufacturer("00:00:00:00:00:00")