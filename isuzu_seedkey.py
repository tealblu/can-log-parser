"""
isuzu_seedkey.py  —  Find Isuzu KWP security-access seed/key exchanges in a CAN log.

Captures all four frames of a complete exchange:
  1. Seed request  : tester  → ECU  (7E0  02 27 01)
  2. Seed response : ECU     → tester  (7E8  04 67 01 <seed_hi> <seed_lo>)
  3. Key send      : tester  → ECU  (7E0  04 27 02 <key_hi> <key_lo>)
  4. Access granted: ECU     → tester  (7E8  02 67 02)

Works on raw Kvaser-style logs regardless of whether the Flg column is present.

Usage:
    python isuzu_seedkey.py <log_file>
"""

import re
import sys
from dataclasses import dataclass
from typing import List, Optional

# ── Log line parser ───────────────────────────────────────────────────────────
# Handles both formats:
#   with flag:     CH  ID        FLAG  DLC  D0 ...  TS  DIR
#   without flag:  CH  ID              DLC  D0 ...  TS  DIR
_LINE_RE = re.compile(
    r'^\s*(\d+)'                              # channel
    r'\s+([0-9A-Fa-f]+)'                     # CAN ID (hex)
    r'(?:\s+[A-Za-z]\w*)?'                   # optional flag token (letters-only start)
    r'\s+(\d+)'                               # DLC
    r'((?:\s+[0-9A-Fa-f]{1,2})+)'           # data bytes
    r'\s+([\d.]+)'                            # timestamp
    r'(?:\s+(\w+))?',                         # optional direction
    re.IGNORECASE,
)


@dataclass
class Frame:
    line_no: int
    can_id: int
    dlc: int
    data: List[int]       # raw byte values
    timestamp: float
    raw: str

    def d(self, idx: int) -> int:
        return self.data[idx] if idx < len(self.data) else -1


def parse_frames(path: str) -> List[Frame]:
    frames = []
    with open(path, 'r', errors='replace') as fh:
        for line_no, raw in enumerate(fh, 1):
            m = _LINE_RE.match(raw)
            if not m:
                continue
            dlc = int(m.group(3))
            byte_strs = m.group(4).split()
            if len(byte_strs) != dlc:
                continue
            try:
                data = [int(b, 16) for b in byte_strs]
                frames.append(Frame(
                    line_no=line_no,
                    can_id=int(m.group(2), 16),
                    dlc=dlc,
                    data=data,
                    timestamp=float(m.group(5)),
                    raw=raw.rstrip(),
                ))
            except ValueError:
                continue
    return frames


# ── Frame classifiers ─────────────────────────────────────────────────────────
ECU_ID  = 0x7E8
TOOL_ID = 0x7E0

def is_seed_request(f: Frame) -> bool:
    """Tester asks for seed: 7E0  02 27 01 ..."""
    return f.can_id == TOOL_ID and f.d(0) == 0x02 and f.d(1) == 0x27 and f.d(2) == 0x01

def is_seed_response(f: Frame) -> bool:
    """ECU sends seed: 7E8  04 67 01 <hi> <lo> ..."""
    return f.can_id == ECU_ID and f.d(0) == 0x04 and f.d(1) == 0x67 and f.d(2) == 0x01

def is_key_send(f: Frame) -> bool:
    """Tester sends key: 7E0  04 27 02 <hi> <lo> ..."""
    return f.can_id == TOOL_ID and f.d(0) == 0x04 and f.d(1) == 0x27 and f.d(2) == 0x02

def is_access_granted(f: Frame) -> bool:
    """ECU confirms access: 7E8  02 67 02 ..."""
    return f.can_id == ECU_ID and f.d(0) == 0x02 and f.d(1) == 0x67 and f.d(2) == 0x02


# ── Known seed/key pairs (from IsuzuKWP_MessageTranslations.cs) ───────────────
_KNOWN = {
    (0x83, 0x40): (0x97, 0x65),
    (0xD5, 0x9A): (0x6A, 0x3C),
}

def _seed_label(hi: int, lo: int) -> str:
    pair = _KNOWN.get((hi, lo))
    if pair:
        return f"{hi:02X} {lo:02X}  (known — expected key {pair[0]:02X} {pair[1]:02X})"
    return f"{hi:02X} {lo:02X}  *** UNKNOWN SEED ***"

def _key_label(hi: int, lo: int, seed_hi: Optional[int], seed_lo: Optional[int]) -> str:
    if seed_hi is not None:
        expected = _KNOWN.get((seed_hi, seed_lo))
        if expected:
            match = "✓ correct" if (hi, lo) == expected else f"✗ wrong (expected {expected[0]:02X} {expected[1]:02X})"
            return f"{hi:02X} {lo:02X}  {match}"
    return f"{hi:02X} {lo:02X}"


# ── Exchange assembly ─────────────────────────────────────────────────────────
def _fmt(f: Frame, role: str) -> str:
    data_str = ' '.join(f'{b:02X}' for b in f.data)
    return (f"  {role:<16} line {f.line_no:>7}  ts={f.timestamp:>12.6f}  "
            f"CAN={f.can_id:08X}  [{data_str}]")

def print_exchanges(frames: List[Frame]) -> None:
    seed_reqs   = [f for f in frames if is_seed_request(f)]
    seed_resps  = [f for f in frames if is_seed_response(f)]
    key_sends   = [f for f in frames if is_key_send(f)]
    access_acks = [f for f in frames if is_access_granted(f)]

    print(f"\nSecurity-access frames found:")
    print(f"  Seed requests  (27 01): {len(seed_reqs)}")
    print(f"  Seed responses (67 01): {len(seed_resps)}")
    print(f"  Key sends      (27 02): {len(key_sends)}")
    print(f"  Access granted (67 02): {len(access_acks)}")

    if not seed_resps:
        print("\nNo seed/key exchanges found in this log.")
        return

    # Pair each seed response with the closest following key send and access ack
    def _next_after(pool: List[Frame], ts: float) -> Optional[Frame]:
        return next((f for f in pool if f.timestamp > ts), None)

    print()
    for i, seed in enumerate(seed_resps, 1):
        seed_hi, seed_lo = seed.d(3), seed.d(4)
        print(f"─── Exchange #{i} ─────────────────────────────────────────────────────")
        req = _next_after(seed_reqs, seed.timestamp - 1.5)   # req comes just before seed
        # find req that precedes this seed
        req = next((f for f in reversed(seed_reqs) if f.timestamp <= seed.timestamp), None)
        key = _next_after(key_sends, seed.timestamp)
        ack = _next_after(access_acks, seed.timestamp)

        if req:
            print(_fmt(req,  "seed request"))
        print(_fmt(seed, "seed response"))
        print(f"    seed value: {_seed_label(seed_hi, seed_lo)}")

        if key:
            key_hi, key_lo = key.d(3), key.d(4)
            print(_fmt(key, "key send"))
            print(f"    key  value: {_key_label(key_hi, key_lo, seed_hi, seed_lo)}")
            if req:
                print(f"    seed→key lag: {(key.timestamp - seed.timestamp)*1000:.1f} ms")
        else:
            print("  key send        (not found)")

        if ack:
            print(_fmt(ack, "access granted"))
            if key:
                print(f"    key→ack  lag: {(ack.timestamp - key.timestamp)*1000:.1f} ms")
        else:
            print("  access granted  (not found)")

        print()


# ── Entry point ───────────────────────────────────────────────────────────────
def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python isuzu_seedkey.py <log_file>")
        sys.exit(1)

    path = sys.argv[1]
    print(f"Parsing {path} ...")
    frames = parse_frames(path)
    print(f"Parsed {len(frames):,} frames total.")
    print_exchanges(frames)


if __name__ == "__main__":
    main()
