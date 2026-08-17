# de-card

Reads a card on a PC/SC contactless reader (e.g. Identiv uTrust 3700 F) and
**types its SHA1 as keyboard input**:

- **MIFARE Classic** — reads sector 15, hashes the number field, types the digest.
- **DESFire / other** — hashes the UID.

## Setup on a fresh Ubuntu PC

### 1. System packages

```bash
sudo apt update
sudo apt install -y pcscd libccid pcsc-tools python3-venv
sudo systemctl enable --now pcscd
```

### 2. Python environment

```bash
python3 -m venv ~/.venvs/nfc
~/.venvs/nfc/bin/pip install "pyscard>=2.3" evdev
```

### 3. Keyboard (uinput) permissions

So the script can type without running as root:

```bash
# udev rule + module load
echo 'KERNEL=="uinput", GROUP="input", MODE="0660", OPTIONS+="static_node=uinput"' \
  | sudo tee /etc/udev/rules.d/99-uinput.rules
echo uinput | sudo tee /etc/modules-load.d/uinput.conf
sudo modprobe uinput

# grant access
sudo usermod -aG input "$USER"
sudo udevadm control --reload-rules && sudo udevadm trigger
```

Then **log out and back in** (group changes only apply to new sessions).

## Run

```bash
~/.venvs/nfc/bin/python card_hash.py
```

Tap a card — the SHA1 is typed (hex + Enter) wherever the cursor is focused.
Stop with Ctrl-C. Errors go to stderr; nothing else is printed.

## Verify (if something fails)

```bash
pcsc_scan                  # reader detected? card ATR shown on tap?
ls -l /dev/uinput          # want: crw-rw---- root input
id | grep -o input         # confirms you're in the input group
```

## Tuning (in card_hash.py)

- `KEYS` — sector-15 keys tried in order (first match wins).
- `SECTOR_OFFSET` / `SECTOR_LENGTH` — which bytes of sector 15 are the number.
- `classic_preimage()` — what exactly gets hashed (raw number vs hex string).
- `TYPE_DELAY` — keystroke spacing; lower it if the target keeps up.