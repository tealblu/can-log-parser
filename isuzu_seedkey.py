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
from pathlib import Path
from typing import Callable

from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, TaskProgressColumn, TextColumn
from rich.table import Table

# Ensure Unicode glyphs (✓ ✗ ● …) render even when output is piped on Windows.
_reconfigure = getattr(sys.stdout, "reconfigure", None)
if callable(_reconfigure):
    try:
        _ = _reconfigure(encoding="utf-8")
    except Exception:
        pass

console = Console()

# ── Log line parser ───────────────────────────────────────────────────────────
# Handles both formats:
#   with flag:     CH  ID        FLAG  DLC  D0 ...  TS  DIR
#   without flag:  CH  ID              DLC  D0 ...  TS  DIR
_LINE_RE = re.compile(
    r"^\s*(\d+)"  # channel
    + r"\s+([0-9A-Fa-f]+)"  # CAN ID (hex)
    + r"(?:\s+[A-Za-z]\w*)?"  # optional flag token (letters-only start)
    + r"\s+(\d+)"  # DLC
    + r"((?:\s+[0-9A-Fa-f]{1,2})+)"  # data bytes
    + r"\s+([\d.]+)"  # timestamp
    + r"(?:\s+(\w+))?",  # optional direction
    re.IGNORECASE,
)


@dataclass
class Frame:
    line_no: int
    can_id: int
    dlc: int
    data: list[int]  # raw byte values
    timestamp: float
    raw: str

    def d(self, idx: int) -> int:
        return self.data[idx] if idx < len(self.data) else -1


def parse_frames(path: str) -> list[Frame]:
    frames: list[Frame] = []
    file_lines = sum(1 for _ in open(path, "r", errors="replace"))

    # Progress bar
    progress = Progress(
        TextColumn("[cyan]Parsing log file..."),
        BarColumn(),
        TaskProgressColumn(),
    )
    with progress:
        task = progress.add_task("parse", total=file_lines)
        with open(path, "r", errors="replace") as fh:
            for line_no, raw in enumerate(fh, 1):
                progress.update(task, advance=1)
                m = _LINE_RE.match(raw)
                if not m:
                    continue
                dlc = int(m.group(3))
                byte_strs = m.group(4).split()
                if len(byte_strs) != dlc:
                    continue
                try:
                    data = [int(b, 16) for b in byte_strs]
                    frames.append(
                        Frame(
                            line_no=line_no,
                            can_id=int(m.group(2), 16),
                            dlc=dlc,
                            data=data,
                            timestamp=float(m.group(5)),
                            raw=raw.rstrip(),
                        )
                    )
                except ValueError:
                    continue
    return frames


# ── Frame classifiers ─────────────────────────────────────────────────────────
ECU_ID = 0x7E8
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


# ── Styling primitives ────────────────────────────────────────────────────────
# One function per semantic role. Each owns exactly one color/element, so the
# palette is defined here once — never inline in the rendering code below.


def success(text: object) -> str:  # green — a confirmed-good outcome
    return f"[bold green]{text}[/bold green]"


def failure(text: object) -> str:  # red — a genuine error / mismatch
    return f"[bold red]{text}[/bold red]"


def warn(text: object) -> str:  # yellow — missing / unknown / unconfirmed
    return f"[yellow]{text}[/yellow]"


def info(text: object) -> str:  # cyan — neutral informational value
    return f"[cyan]{text}[/cyan]"


def muted(text: object) -> str:  # dim — secondary detail
    return f"[dim]{text}[/dim]"


def label(text: object) -> str:  # bold — field name
    return f"[bold]{text}[/bold]"


def value(text: object) -> str:  # bold white — a raw hex datum
    return f"[bold white]{text}[/bold white]"


def hex_bytes(data: list[int]) -> str:
    return " ".join(f"{b:02X}" for b in data)


def hex_pair(hi: int, lo: int) -> str:
    return f"{hi:02X} {lo:02X}"


# Status dots — one element, colored by the helper that owns each role.
DOT = "●"
MISSING_DOT = "○"


# ── Known seed/key pairs (from IsuzuKWP_MessageTranslations.cs) ───────────────
_KNOWN = {
    (0x83, 0x40): (0x97, 0x65),
    (0xD5, 0x9A): (0x6A, 0x3C),
}


def _seed_label(hi: int, lo: int) -> str:
    pair = _KNOWN.get((hi, lo))
    hex_val = value(hex_pair(hi, lo))
    if pair:
        return f"{hex_val}  {info(f'(known — expected key {hex_pair(*pair)})')}"
    return f"{hex_val}  {warn('⚠ unrecognized seed')}"


def _key_label(hi: int, lo: int, seed_hi: int | None, seed_lo: int | None) -> str:
    hex_val = value(hex_pair(hi, lo))
    if seed_hi is not None and seed_lo is not None:
        expected = _KNOWN.get((seed_hi, seed_lo))
        if expected:
            if (hi, lo) == expected:
                status = success("✓ CORRECT")
            else:
                status = (
                    f"{failure('✗ WRONG')} {muted(f'(expected {hex_pair(*expected)})')}"
                )
            return f"{hex_val}  {status}"
    return hex_val


# ── Exchange assembly ─────────────────────────────────────────────────────────
def print_exchanges(frames: list[Frame]) -> None:
    seed_reqs = [f for f in frames if is_seed_request(f)]
    seed_resps = [f for f in frames if is_seed_response(f)]
    key_sends = [f for f in frames if is_key_send(f)]
    access_acks = [f for f in frames if is_access_granted(f)]

    summary_table = Table(
        title="Security-Access Frames Found", show_header=False, box=None
    )
    summary_table.add_row("Seed requests  (27 01):", info(len(seed_reqs)))
    summary_table.add_row("Seed responses (67 01):", info(len(seed_resps)))
    summary_table.add_row("Key sends      (27 02):", info(len(key_sends)))
    summary_table.add_row("Access granted (67 02):", info(len(access_acks)))
    console.print(summary_table)

    if not seed_resps:
        console.print("\n" + warn("No seed/key exchanges found in this log."))
        return

    console.print()

    def _next_after(pool: list[Frame], ts: float) -> Frame | None:
        return next((f for f in pool if f.timestamp > ts), None)

    for i, seed in enumerate(seed_resps, 1):
        seed_hi, seed_lo = seed.d(3), seed.d(4)
        req = next(
            (f for f in reversed(seed_reqs) if f.timestamp <= seed.timestamp), None
        )
        key = _next_after(key_sends, seed.timestamp)
        ack = _next_after(access_acks, seed.timestamp)

        lines: list[str] = []

        def present_frame(
            name: str, f: Frame, *, dot: Callable[[object], str] = info
        ) -> None:
            """Render a frame that was found: colored dot + header + its raw bytes."""
            lines.append(
                f"{dot(DOT)} {label(name)}  "
                + muted(f"line {f.line_no}  ts={f.timestamp:.6f}  CAN={f.can_id:08X}")
            )
            lines.append("  " + muted(hex_bytes(f.data)))

        def missing_frame(name: str, note: str) -> None:
            """Render a frame that was expected but not found."""
            lines.append(f"{warn(MISSING_DOT)} {warn(name)}  {warn(f'({note})')}")

        def detail(text: str) -> None:
            lines.append("  " + muted(text))

        # 1 — Seed request (tester → ECU). Informational step.
        if req:
            present_frame("Seed Request", req)
        else:
            missing_frame("Seed Request", "not found")

        # 2 — Seed response (ECU → tester). Informational step.
        present_frame("Seed Response", seed)
        lines.append("  " + label("Seed:") + f" {_seed_label(seed_hi, seed_lo)}")

        # 3 — Key send (tester → ECU). Informational step.
        if key:
            key_hi, key_lo = key.d(3), key.d(4)
            present_frame("Key Send", key)
            lines.append(
                "  "
                + label("Key:")
                + f"  {_key_label(key_hi, key_lo, seed_hi, seed_lo)}"
            )
            detail(f"Seed→Key lag: {(key.timestamp - seed.timestamp) * 1000:.1f} ms")
        else:
            missing_frame("Key Send", "not found")

        # 4 — Access granted (ECU → tester). The actual outcome: success.
        if ack:
            present_frame("Access Granted", ack, dot=success)
            lines.append("  " + success("✓ SECURITY ACCESS GRANTED"))
            if key:
                detail(f"Key→Ack lag: {(ack.timestamp - key.timestamp) * 1000:.1f} ms")
        else:
            missing_frame("Access Granted", "not found — access not confirmed")

        # Panel border + title marker reflect the exchange outcome.
        if ack:
            border, title_tag = "green", success("✓")
        else:
            border, title_tag = "yellow", warn("…")

        panel = Panel(
            "\n".join(lines), title=f"{title_tag} Exchange #{i}", border_style=border
        )
        console.print(panel)


# ── Entry point ───────────────────────────────────────────────────────────────
def main() -> None:
    if len(sys.argv) < 2:
        console.print(f"{failure('Usage:')} python isuzu_seedkey.py <log_file>")
        sys.exit(1)

    path = sys.argv[1]
    if not Path(path).exists():
        console.print(f"{failure('Error:')} File not found: {path}")
        sys.exit(1)

    console.print(f"\n{label('Parsing')} {path} ...")
    frames = parse_frames(path)

    summary = Panel(
        f"{info(f'{len(frames):,}')} frames parsed",
        title=label("Parse Complete"),
        expand=False,
    )
    console.print(summary)
    print_exchanges(frames)


if __name__ == "__main__":
    main()
