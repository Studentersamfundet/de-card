#!/usr/bin/env python3
"""
Read a card on a PC/SC contactless reader and TYPE its SHA1 as a keyboard.

  MIFARE Classic  -> authenticate + read sector 15, hash the number field
  DESFire / other -> read the UID, hash it

The digest is emitted as keystrokes (hex + Enter) via a synthesized uinput
device, exactly like the original wedge script -- so downstream apps see it
as normal keyboard input.

Requires: pcscd running, `pip install "pyscard>=2.3" evdev`.
Needs write access to /dev/uinput (run as root, or add a udev rule and put
your user in the `input` group).
"""

import hashlib
import signal
import sys
import threading
import time

from smartcard.CardMonitoring import CardMonitor, CardObserver
from smartcard.Exceptions import CardConnectionException, NoCardException

try:
    import evdev
    from evdev import ecodes as e
except ImportError:
    evdev = None

# ---------------------------------------------------------------------------
# configuration
# ---------------------------------------------------------------------------
# Sector-15 keys to try, in order. First one that authenticates wins.
KEYS = [
    "447524F55503",
    "000000000000",
    "FFFFFFFFFFFF",
]
KEY_TYPE = 0x60                               # 0x60 = Key A, 0x61 = Key B
_KEYS = [list(bytes.fromhex(k)) for k in KEYS]
SECTOR = 15                                   # MIFARE Classic 1K/4K: blocks 60-63
DATA_BLOCKS = [SECTOR * 4 + i for i in range(3)]   # 60, 61, 62 (63 is trailer)

# Byte range within the concatenated sector-15 data (blocks 60-62 => 48 bytes)
# that holds the number. Here it's the ASCII digits "215387" at offset 19.
SECTOR_OFFSET = 19
SECTOR_LENGTH = 6

TYPE_DELAY = 0.002                            # seconds between keystrokes


# --- WHAT GETS HASHED -------------------------------------------------------
def classic_preimage(sector_bytes: list[int]) -> bytes:
    end = len(sector_bytes) if SECTOR_LENGTH is None else SECTOR_OFFSET + SECTOR_LENGTH
    chunk = bytes(sector_bytes[SECTOR_OFFSET:end])
    return chunk                              # raw bytes -> here ASCII b"215387"
    # Alternative: hash the uppercase hex string b"323135333837" instead:
    # return chunk.hex().upper().encode("utf-8")

def uid_preimage(uid_bytes: list[int]) -> bytes:
    return "".join(f"{b:02X}" for b in uid_bytes).encode("utf-8")
# ---------------------------------------------------------------------------


class Keyboard:
    """Synthesized uinput keyboard that types ASCII (hex digest + newline)."""

    def __init__(self):
        if evdev is None:
            raise RuntimeError("python-evdev not installed (pip install evdev)")
        self._map = {}
        for c in "abcdefghijklmnopqrstuvwxyz":
            self._map[c] = getattr(e, f"KEY_{c.upper()}")
        for c in "0123456789":
            self._map[c] = getattr(e, f"KEY_{c}")
        self._map[" "] = e.KEY_SPACE
        self._map["\n"] = e.KEY_ENTER
        caps = {e.EV_KEY: sorted(set(self._map.values()))}
        self._ui = evdev.UInput(caps, name="card-hash-kbd")
        time.sleep(0.3)                       # let the OS register the device

    def type(self, text: str) -> None:
        for ch in text:
            code = self._map.get(ch)
            if code is None:
                continue
            self._ui.write(e.EV_KEY, code, 1)  # press
            self._ui.write(e.EV_KEY, code, 0)  # release
            self._ui.syn()
            time.sleep(TYPE_DELAY)

    def close(self) -> None:
        try:
            self._ui.close()
        except Exception:
            pass


# PC/SC storage-card RID; its trailing name bytes identify the card family.
_STORAGE_RID = [0xA0, 0x00, 0x00, 0x03, 0x06]
_CARD_NAMES = {
    (0x00, 0x01): "classic1k", (0x00, 0x02): "classic4k",
    (0x00, 0x03): "ultralight", (0x00, 0x26): "mini",
}

GET_UID = [0xFF, 0xCA, 0x00, 0x00, 0x00]


def _find(seq, sub):
    for i in range(len(seq) - len(sub) + 1):
        if seq[i:i + len(sub)] == sub:
            return i
    return -1


def classify(atr) -> str:
    """Return card family from the PC/SC ATR."""
    b = list(atr)
    idx = _find(b, _STORAGE_RID)
    if idx >= 0 and idx + 7 < len(b):
        name = (b[idx + 6], b[idx + 7])          # skip the SS standard byte
        return _CARD_NAMES.get(name, "storage-other")
    return "iso14443-4"                          # DESFire and other T=CL cards


def load_key(key):
    return [0xFF, 0x82, 0x00, 0x00, 0x06] + key

def authenticate(block, key_type):
    return [0xFF, 0x86, 0x00, 0x00, 0x05, 0x01, 0x00, block, key_type, 0x00]

def read_binary(block, length=16):
    return [0xFF, 0xB0, 0x00, block, length]


def _ok(sw1, sw2):
    return (sw1, sw2) == (0x90, 0x00)


class HashTyper(CardObserver):
    def __init__(self, keyboard: Keyboard):
        super().__init__()
        self.kbd = keyboard

    def update(self, observable, handlers) -> None:
        added, _removed = handlers
        for card in added:
            try:
                conn = card.createConnection()
                conn.connect()
            except (NoCardException, CardConnectionException) as exc:
                print(f"connect failed: {exc}", file=sys.stderr, flush=True)
                continue
            try:
                kind = classify(conn.getATR())
                if kind in ("classic1k", "classic4k"):
                    digest = self._classic(conn)
                else:
                    digest = self._uid(conn, kind)
                if digest:
                    self.kbd.type(digest + "\n")   # type it like a keyboard
            finally:
                conn.disconnect()

    def _classic(self, conn):
        for i, key in enumerate(_KEYS):
            if i > 0:
                # A failed crypto1 auth can halt the card; re-activate before retry.
                try:
                    conn.reconnect()
                except CardConnectionException:
                    pass
            _, sw1, sw2 = conn.transmit(load_key(key))
            if not _ok(sw1, sw2):
                continue
            _, sw1, sw2 = conn.transmit(authenticate(DATA_BLOCKS[0], KEY_TYPE))
            if _ok(sw1, sw2):
                break
        else:
            print(f"sector {SECTOR} auth failed with all {len(_KEYS)} keys",
                  file=sys.stderr, flush=True)
            return None
        buf = []
        for blk in DATA_BLOCKS:
            data, sw1, sw2 = conn.transmit(read_binary(blk))
            if not _ok(sw1, sw2):
                print(f"read block {blk} failed SW={sw1:02X}{sw2:02X}",
                      file=sys.stderr, flush=True)
                return None
            buf += data
        return hashlib.sha1(classic_preimage(buf)).hexdigest()

    def _uid(self, conn, kind):
        data, sw1, sw2 = conn.transmit(GET_UID)
        if not _ok(sw1, sw2):
            print(f"UID read failed SW={sw1:02X}{sw2:02X}", file=sys.stderr, flush=True)
            return None
        return hashlib.sha1(uid_preimage(data)).hexdigest()


def main() -> int:
    try:
        keyboard = Keyboard()
    except Exception as exc:
        print(f"cannot open uinput keyboard: {exc}", file=sys.stderr)
        print("Need write access to /dev/uinput. Run as root, or add a udev rule "
              "granting the `input` group and add yourself to it.", file=sys.stderr)
        return 1

    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())

    monitor = CardMonitor()
    observer = HashTyper(keyboard)
    monitor.addObserver(observer)
    try:
        stop.wait()
    finally:
        monitor.deleteObserver(observer)
        keyboard.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())