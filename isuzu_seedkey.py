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
from pathlib import Path
from rich.console import Console
from rich.progress import Progress
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

console = Console()

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
    file_lines = sum(1 for _ in open(path, 'r', errors='replace'))

    with Progress() as progress:
        task = progress.add_task("[cyan]Parsing log file...", total=file_lines)
        with open(path, 'r', errors='replace') as fh:
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
    hex_val = f"[bold yellow]{hi:02X} {lo:02X}[/bold yellow]"
    if pair:
        return f"{hex_val}  [dim](known — expected key {pair[0]:02X} {pair[1]:02X})[/dim]"
    return f"{hex_val}  [bold red]UNKNOWN[/bold red]"

def _key_label(hi: int, lo: int, seed_hi: Optional[int], seed_lo: Optional[int]) -> str:
    hex_val = f"[bold cyan]{hi:02X} {lo:02X}[/bold cyan]"
    if seed_hi is not None:
        expected = _KNOWN.get((seed_hi, seed_lo))
        if expected:
            if (hi, lo) == expected:
                status = "[bold green]✓ CORRECT[/bold green]"
            else:
                status = f"[bold red]✗ WRONG[/bold red] [dim](expected {expected[0]:02X} {expected[1]:02X})[/dim]"
            return f"{hex_val}  {status}"
    return hex_val


# ── Exchange assembly ─────────────────────────────────────────────────────────
def print_exchanges(frames: List[Frame]) -> None:
    seed_reqs   = [f for f in frames if is_seed_request(f)]
    seed_resps  = [f for f in frames if is_seed_response(f)]
    key_sends   = [f for f in frames if is_key_send(f)]
    access_acks = [f for f in frames if is_access_granted(f)]

    summary_table = Table(title="Security-Access Frames Found", show_header=False, box=None)
    summary_table.add_row("Seed requests  (27 01):", f"[cyan]{len(seed_reqs)}[/cyan]")
    summary_table.add_row("Seed responses (67 01):", f"[cyan]{len(seed_resps)}[/cyan]")
    summary_table.add_row("Key sends      (27 02):", f"[cyan]{len(key_sends)}[/cyan]")
    summary_table.add_row("Access granted (67 02):", f"[cyan]{len(access_acks)}[/cyan]")
    console.print(summary_table)

    if not seed_resps:
        console.print("\n[yellow]No seed/key exchanges found in this log.[/yellow]")
        return

    console.print()

    def _next_after(pool: List[Frame], ts: float) -> Optional[Frame]:
        return next((f for f in pool if f.timestamp > ts), None)

    for i, seed in enumerate(seed_resps, 1):
        seed_hi, seed_lo = seed.d(3), seed.d(4)
        req = next((f for f in reversed(seed_reqs) if f.timestamp <= seed.timestamp), None)
        key = _next_after(key_sends, seed.timestamp)
        ack = _next_after(access_acks, seed.timestamp)

        lines = []

        if req:
            data_str = ' '.join(f'{b:02X}' for b in req.data)
            lines.append(f"[green]Seed Request[/green]  line {req.line_no}  ts={req.timestamp:.6f}  CAN={req.can_id:08X}")
            lines.append(f"  [dim]{data_str}[/dim]")

        data_str = ' '.join(f'{b:02X}' for b in seed.data)
        lines.append(f"[magenta]Seed Response[/magenta]  line {seed.line_no}  ts={seed.timestamp:.6f}  CAN={seed.can_id:08X}")
        lines.append(f"  [dim]{data_str}[/dim]")
        seed_label = _seed_label(seed_hi, seed_lo)
        lines.append(f"  [bold]Seed:[/bold] {seed_label}")

        if key:
            key_hi, key_lo = key.d(3), key.d(4)
            data_str = ' '.join(f'{b:02X}' for b in key.data)
            lines.append(f"[blue]Key Send[/blue]  line {key.line_no}  ts={key.timestamp:.6f}  CAN={key.can_id:08X}")
            lines.append(f"  [dim]{data_str}[/dim]")
            key_label = _key_label(key_hi, key_lo, seed_hi, seed_lo)
            lines.append(f"  [bold]Key:[/bold] {key_label}")
            lag_ms = (key.timestamp - seed.timestamp) * 1000
            lines.append(f"  [dim]Seed→Key lag: {lag_ms:.1f} ms[/dim]")
        else:
            lines.append("[yellow]Key Send[/yellow]  (not found)")

        if ack:
            data_str = ' '.join(f'{b:02X}' for b in ack.data)
            lines.append(f"[green]Access Granted[/green]  line {ack.line_no}  ts={ack.timestamp:.6f}  CAN={ack.can_id:08X}")
            lines.append(f"  [dim]{data_str}[/dim]")
            if key:
                lag_ms = (ack.timestamp - key.timestamp) * 1000
                lines.append(f"  [dim]Key→Ack lag: {lag_ms:.1f} ms[/dim]")
        else:
            lines.append("[yellow]Access Granted[/yellow]  (not found)")

        content = "\n".join(lines)
        panel = Panel(content, title=f"Exchange #{i}")
        console.print(panel)


# ── Entry point ───────────────────────────────────────────────────────────────
def main() -> None:
    if len(sys.argv) < 2:
        console.print("[red]Usage:[/red] python isuzu_seedkey.py <log_file>")
        sys.exit(1)

    path = sys.argv[1]
    if not Path(path).exists():
        console.print(f"[red]Error:[/red] File not found: {path}")
        sys.exit(1)

    console.print(f"\n[bold]Parsing[/bold] {path} ...")
    frames = parse_frames(path)

    summary = Panel(
        f"[cyan]{len(frames):,}[/cyan] frames parsed",
        title="[bold]Parse Complete[/bold]",
        expand=False
    )
    console.print(summary)
    print_exchanges(frames)


if __name__ == "__main__":
    main()
