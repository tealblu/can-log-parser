# CAN / J1939 Log Analysis

A handful of standalone Python scripts for digging through automotive CAN / J1939
diagnostic logs — locating specific commands, and finding UDS/KWP security-access
(seed/key) exchanges.

All algorithms here were derived firsthand from my own captured diagnostic
sessions. No proprietary OEM material is included.

## Requirements

- Python 3.11+
- `rich` (only for `isuzu_seedkey.py`; the others are stdlib-only)

```bash
pip install -r requirements.txt
```

Put your log files in `logs/` (git-ignored — logs are large and vehicle-specific).

## Scripts

### `find_security_access.py`
Finds the UDS Security Access (service `0x27`) seed/key sequence in a J1939 /
ISO-TP log, reports the diagnostic session in effect, surfaces any raw PIN
payload, and flags anomalies (e.g. `invalidKey 0x35`, `exceededNumberOfAttempts
0x36`). Built for a Hino J08E session but works on any UDS-over-J1939 capture.

```bash
python find_security_access.py logs/hino_log_1.txt [--format raw]
```

Only one log format (`raw`, a Vehicle Spy / generic CAN dump) is implemented. For
a different export, edit `parse_line()` — it's the only format-specific code.

### `isuzu_seedkey.py`
Finds Isuzu **KWP** security-access seed/key exchanges, capturing all four frames
of a complete handshake (seed request → seed response → key send → access
granted). Handles Kvaser-style logs with or without the flag column.

```bash
python isuzu_seedkey.py logs/log.txt
```

### `CANalyzer.py`
Locates a specific command/routine in one or more logs by matching CAN message
patterns — useful for correlating a known action (e.g. video timestamps) to the
CAN frames that fired it. Supports multi-log scanning, offset/relative-time
search, and absolute-time modes.

Configured by editing the `CONFIG` dict at the top of the file (command name,
log paths, format, search parameters), then:

```bash
python CANalyzer.py
```

## Notes

- Log files and `__pycache__` are git-ignored.
- `pyrightconfig.json` configures type checking.
