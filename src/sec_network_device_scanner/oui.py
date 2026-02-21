from __future__ import annotations

from manuf import manuf


class OUILookup:
    """
    Thin wrapper around `manuf` OUI database.
    """

    def __init__(self) -> None:
        self._parser = manuf.MacParser()

    def manufacturer(self, mac: str) -> str | None:
        m = mac.strip().replace("-", ":").upper()

        # Locally administered MAC: second least significant bit of first octet is 1
        try:
            first_octet = int(m.split(":")[0], 16)
            locally_administered = bool(first_octet & 0b00000010)
            if locally_administered:
                return "Local / randomized MAC"
        except Exception:
            pass

        return self._parser.get_manuf(m)
