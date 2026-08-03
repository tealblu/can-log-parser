#!/usr/bin/env python3
"""Find the UDS Security Access (0x27) sequence + PIN entry in a CAN/J1939 log.

Context: Hino J08E (Kobelco SK300) diagnostic session over J1939 29-bit with UDS
on ISO-TP. Technician entered PIN "LB08605014" and it didn't take. This locates
the seed/key exchange, the session in effect, and any raw PIN payload, then flags
anomalies.

Usage:  python find_security_access.py logs/hino_log_1.txt [--format raw]

Stdlib only. Point --format at your export type; if the real file differs, edit
parse_line() in the PARSER CONFIG block below — that's the only format-specific code.
"""

import argparse
import re
import sys

PIN = "LB08605014"

# ---------------------------------------------------------------------------
# PARSER CONFIG  --  the ONLY format-specific code. Add a branch per --format.
# ---------------------------------------------------------------------------
# Observed "raw" format (Vehicle Spy / generic CAN dump), whitespace-separated:
#   " 0    18DAF13D X       8  CD  40  1F  FF  FF  FF  FF  15   0.006120 R"
#    chan  CAN-ID   X  DLC  <--------- 8 data bytes ---------->  timestamp  dir
# 29-bit ID = PRIO(1) PGN-PF(1) PGN-PS/target(1) SA/source(1). For UDS the PF is
# 0xDA (destination-specific diagnostic PGN); target=PS byte, source=SA byte.
# ASSUMPTIONS: extended ID hex w/o 0x; DLC then that many hex data bytes; float
# seconds timestamp near the end. Adjust the regex/indices here for .asc/.trc/csv.

_RAW = re.compile(
    r"^\s*\d+\s+([0-9A-Fa-f]{1,8})\s+X\s+(\d+)\s+((?:[0-9A-Fa-f]{2}\s+){0,8})\s*([\d.]+)\s+[RT]"
)


def parse_line(line, fmt):
    """Return (timestamp_float, can_id_int, data_bytes) or None if not a frame."""
    if fmt == "raw":
        m = _RAW.match(line)
        if not m:
            return None
        can_id = int(m.group(1), 16)
        data = bytes(int(b, 16) for b in m.group(3).split())
        return float(m.group(4)), can_id, data
    # ponytail: one format implemented; add elif fmt == "asc"/"csv" when you hit one.
    raise SystemExit(f"unknown --format {fmt!r}; implement it in parse_line()")


# ---------------------------------------------------------------------------
# UDS decode tables
# ---------------------------------------------------------------------------
UDS_PF = 0xDA  # J1939 PF byte marking the destination-specific diagnostic PGN
NRC = {
    0x10: "generalReject", 0x11: "serviceNotSupported", 0x12: "subFunctionNotSupported",
    0x13: "incorrectMessageLengthOrInvalidFormat", 0x22: "conditionsNotCorrect",
    0x24: "requestSequenceError", 0x31: "requestOutOfRange",
    0x33: "securityAccessDenied",
    0x35: "invalidKey",                       # <-- wrong PIN/key
    0x36: "exceededNumberOfAttempts",         # <-- locked out
    0x37: "requiredTimeDelayNotExpired",      # <-- must wait before retry
    0x78: "responsePending (busy, more coming)",
    0x7E: "subFunctionNotSupportedInActiveSession",
    0x7F: "serviceNotSupportedInActiveSession",
}
SESSION = {0x01: "Default", 0x02: "Programming", 0x03: "Extended", 0x04: "SafetySystem"}


def target_source(can_id):
    """For a 29-bit UDS id: (pf, target_addr, source_addr)."""
    return (can_id >> 16) & 0xFF, (can_id >> 8) & 0xFF, can_id & 0xFF


# ---------------------------------------------------------------------------
# ISO-TP reassembly. Without this, bytes *inside* multiframe payloads (e.g. a
# consecutive frame starting 0x27) masquerade as service IDs -> false positives.
# ---------------------------------------------------------------------------
def iso_tp_messages(frames):
    """Yield (timestamp, can_id, uds_payload) for each reassembled UDS message.

    ponytail: single global dict keyed by (target,source); assumes no interleaved
    multiframe sessions on the same address pair (true for a one-tester bench log).
    """
    pending = {}  # (target,source) -> {"ts", "need", "buf"}
    for ts, can_id, data in frames:
        pf, tgt, src = target_source(can_id)
        if pf != UDS_PF or not data:
            continue
        key = (tgt, src)
        pci = data[0] >> 4
        if pci == 0:  # single frame: low nibble = length
            length = data[0] & 0x0F
            yield ts, can_id, data[1:1 + length]
        elif pci == 1:  # first frame: 12-bit length, 6 payload bytes follow
            length = ((data[0] & 0x0F) << 8) | data[1]
            pending[key] = {"ts": ts, "need": length, "buf": bytearray(data[2:])}
        elif pci == 2:  # consecutive frame: append (ignore seq counter, best-effort)
            st = pending.get(key)
            if st:
                st["buf"].extend(data[1:])
                if len(st["buf"]) >= st["need"]:
                    yield st["ts"], can_id, bytes(st["buf"][:st["need"]])
                    del pending[key]
        # pci == 3 (flow control) carries no payload; skip.


# ---------------------------------------------------------------------------
# Message-level analysis
# ---------------------------------------------------------------------------
def annotate(payload):
    """Plain-English annotation for a UDS message + a 'kind' tag for anomaly logic."""
    if not payload:
        return None, ""
    sid = payload[0]
    if sid == 0x10 and len(payload) >= 2:
        s = payload[1] & 0x7F
        return "session", f"DiagSessionControl -> {SESSION.get(s, f'0x{s:02X}')} session"
    if sid == 0x50 and len(payload) >= 2:
        s = payload[1] & 0x7F
        return "session_ok", f"Session control OK -> {SESSION.get(s, f'0x{s:02X}')} active"
    if sid == 0x27 and len(payload) >= 2:
        sub = payload[1]
        if sub % 2 == 1:
            return "seed_req", f"Seed request (level 0x{sub:02X})"
        return "key_send", f"Key send (level 0x{sub:02X}), key={payload[2:].hex(' ')}"
    if sid == 0x67 and len(payload) >= 2:
        sub = payload[1]
        if sub % 2 == 1:
            return "seed_resp", f"Seed response (level 0x{sub:02X}), seed={payload[2:].hex(' ')}"
        return "key_ok", f"Key accepted (level 0x{sub:02X}) -- security unlocked"
    if sid == 0x7F and len(payload) >= 3:
        svc, nrc = payload[1], payload[2]
        note = f"NEGATIVE response to service 0x{svc:02X}: {NRC.get(nrc, f'NRC 0x{nrc:02X}')}"
        return ("nrc27" if svc == 0x27 else "nrc"), note
    return None, ""  # other services (0x22 RDBI, 0x19 ReadDTC, ...) not of interest


def find_pin_hits(path, fmt):
    """Scan raw log for the PIN as ASCII text and as space/compact hex payload."""
    ascii_bytes = PIN.encode()
    hex_compact = ascii_bytes.hex()               # 4c4230383630353031 34
    hex_spaced = ascii_bytes.hex(" ").upper()     # 4C 42 30 38 ...
    hits = []
    with open(path, "r", errors="replace") as fh:
        for n, line in enumerate(fh, 1):
            low = line.lower()
            if (PIN.lower() in low or hex_compact in low
                    or hex_spaced.lower() in low):
                hits.append((n, line.rstrip()))
    return hits


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("logfile")
    ap.add_argument("--format", default="raw", help="log export format (default: raw)")
    args = ap.parse_args()

    # Pass 1: reassembled UDS messages of interest.
    def frame_iter():
        with open(args.logfile, "r", errors="replace") as fh:
            for line in fh:
                f = parse_line(line, args.format)
                if f:
                    yield f

    events = []  # (ts, can_id, kind, note, payload)
    for ts, can_id, payload in iso_tp_messages(frame_iter()):
        kind, note = annotate(payload)
        if kind:
            events.append((ts, can_id, kind, note, payload))
    events.sort(key=lambda e: e[0])

    # Pass 2: literal PIN scan (independent of ISO-TP, in case it was sent raw).
    pin_hits = find_pin_hits(args.logfile, args.format)

    # ---- report ----
    print(f"\n=== UDS session/security events ({len(events)}) ===")
    if not events:
        print("  (none found -- no 0x10 session control and no 0x27 security access "
              "in this capture)")
    for ts, can_id, kind, note, payload in events:
        _, tgt, src = target_source(can_id)
        print(f"  {ts:12.6f}  {can_id:08X} (tgt {tgt:02X}<-src {src:02X})  "
              f"[{payload.hex(' ')}]  {note}")

    print(f"\n=== PIN '{PIN}' raw scan ({len(pin_hits)} hits) ===")
    if not pin_hits:
        print("  (not present as ASCII text, compact hex, or spaced hex)")
    for n, line in pin_hits[:20]:
        print(f"  line {n}: {line}")

    # ---- anomaly flags ----
    print("\n=== ANOMALIES ===")
    flags = []
    kinds = [e[2] for e in events]
    seeds_seen = {}
    last_session = None
    seed_pending = False
    for ts, _, kind, _, payload in events:
        if kind == "session_ok":
            last_session = payload[1] & 0x7F if len(payload) >= 2 else None
        if kind == "seed_req":
            seed_pending = True
            if last_session not in (0x02, 0x03):
                flags.append(f"{ts:.6f}: seed requested but session is "
                             f"{SESSION.get(last_session, 'unknown/Default')} "
                             "(security usually needs Extended/Programming)")
        if kind == "seed_resp":
            seed = bytes(payload[2:])
            if seed in seeds_seen:
                flags.append(f"{ts:.6f}: REUSED seed {seed.hex(' ')} "
                             f"(also at {seeds_seen[seed]:.6f}) -- ECU may not be "
                             "issuing fresh seeds")
            seeds_seen[seed] = ts
        if kind == "key_send" and not seed_pending:
            flags.append(f"{ts:.6f}: key sent with no preceding seed request")
        if kind in ("key_ok", "nrc27"):
            seed_pending = False
        if kind == "nrc27":
            flags.append(f"{ts:.6f}: security access REJECTED -> {payload[2:].hex(' ')} "
                         "(see NRC decode above)")

    if "seed_req" not in kinds and "key_send" not in kinds:
        flags.append("No SecurityAccess (0x27) exchange at all -- the PIN/seed-key "
                     "step is not in this capture (wrong bus/channel, not logged, or "
                     "done out-of-band).")
    if pin_hits and "key_send" not in kinds:
        flags.append("PIN string present in log but no 0x27 key frame -- possibly sent "
                     "as raw payload rather than through proper seed-key.")
    if not flags:
        print("  (none)")
    for f in flags:
        print(f"  ! {f}")
    print()


# ---------------------------------------------------------------------------
def _selfcheck():
    """assert-based check of the parse + ISO-TP + decode path. Run: python file.py --test"""
    # Single-frame seed request, seed response, key send, negative(invalidKey).
    lines = [
        " 0    18DA00F1 X       8  02  27  01  CC  CC  CC  CC  CC     1.000000 R",  # seed req L1
        " 0    18DAF100 X       8  06  67  01  DE  AD  BE  EF  55     1.010000 R",  # seed resp
        " 0    18DA00F1 X       8  06  27  02  11  22  33  44  CC     1.020000 R",  # key send L2
        " 0    18DAF100 X       8  03  7F  27  35  55  55  55  55     1.030000 R",  # NRC invalidKey
    ]
    frames = [parse_line(x, "raw") for x in lines]
    assert all(frames), "parse_line failed on known-good raw frames"
    msgs = list(iso_tp_messages(iter(frames)))
    kinds = [annotate(p)[0] for _, _, p in msgs]
    assert kinds == ["seed_req", "seed_resp", "key_send", "nrc27"], kinds
    # NRC 0x35 decodes to invalidKey.
    assert "invalidKey" in annotate(msgs[3][2])[1]
    # Consecutive-frame byte 0x27 must NOT be read as a service (regression on the
    # false-positive that motivated ISO-TP reassembly).
    cf = parse_line(" 0    18DAF13D X       8  27  8D  00  40  06  0C  00  40  1.0 R", "raw")
    assert (cf[2][0] >> 4) == 2, "0x27 here is a consecutive-frame PCI, not a SID"
    print("selfcheck OK")


if __name__ == "__main__":
    if "--test" in sys.argv:
        _selfcheck()
    else:
        main()
