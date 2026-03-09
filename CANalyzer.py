import math
import os
import re
import statistics
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List, Optional, Tuple, Dict, Set, Any, Callable

# ============================================================================
# CONFIGURATION - Edit these settings to customize command detection
# ============================================================================
CONFIG = {
    # Command/Test identification
    'command_name': 'INT CylCutout START',  # Name of the command being searched for
    'description': 'CAN message pattern detection for cylinder cutout routine start',

    # Log file paths
    'log_directory': 'logs',
    'log_filename': 'NULN3R32.LOG',
    'full_log_path': lambda: f"{CONFIG['log_directory']}/{CONFIG['log_filename']}",

    # Log format - swap this to change which format is parsed
    # Use: KvaserLogFormat() or NexiqLogFormat()
    'log_format': None,  # Set to None to auto-detect, or set explicitly

    # Multi-log analysis configuration
    'multi_log_paths': None,   # List of log file paths or directory to scan
    'max_cross_log_results': 20,  # Maximum number of ranked matches to display

    # ---- Absolute mode -------------------------------------------------------
    # Command fire times - use the same numeric value as the timestamp in your log:
    #   Kvaser   : the float timestamp printed in the log (e.g. 1234.567890)
    #   Nexiq    : the timestamp float as it appears in the log (e.g. 12332.5)
    # Set to None (and populate relative_fire_times) to use offset-search mode.
    'command_fire_times': None,
    'log_start_time': 0.0,
    'routine_start_time': None,  # Optional; leave None if not needed

    # ---- Offset-search mode --------------------------------------------------
    # Use when you don't know how the video aligns to the log.
    # Provide the command fire times in seconds measured from the START of your
    # video (i.e. t=0 is the first command in the video).  The algorithm slides
    # this template across the log and returns the best-fitting (pattern, offset)
    # pairs, where offset is the log timestamp that corresponds to video t=0.
    # When this is set (not None), command_fire_times is ignored.
    'relative_fire_times': [0, 13, 19, 28, 41, 51, 59, 67, 73, 81],  # e.g. [0, 13, 19, 28, 41, 51, 59, 67, 73, 81]
    # Patterns with more than (n_fire_times * max_occurrences_per_slot) occurrences
    # inside the session window are skipped as likely high-frequency background noise.
    'max_occurrences_per_slot': 2.0,

    # Detection algorithm parameters
    'search_radius': 1,         # ± seconds around each fire time to search
    'min_coverage': 0.5,        # Minimum fraction of fire_times that must match (0.0-1.0)
    'max_candidates': 15,       # Maximum number of results to return
    'expected_occurrence_count': None,  # Optional exact occurrence count filter for patterns

    # Output formatting
    'print_log_summary': True,  # Print CAN log statistics before detection
    'print_verbose': True,      # Print detailed output
    'timestamp_precision': 6,   # Decimal places for timestamp display
    'pattern_display_width': 30,  # Max width for displaying data pattern
    'confidence_precision': 3,  # Decimal places for confidence scores
    'p_value_precision': 3,     # Significant figures for binomial p-value display
    'delta_precision': 3,       # Decimal places for timing deltas
    'table_column_widths': {
        'rank': 5,
        'can_id': 12,
        'pattern': 30,
        'coverage': 10,
        'median_delta': 10,
        'avg_delta': 10,
        'max_delta': 10,
        'offset': 16,           # used by print_offset_candidates
        'confidence': 12,
        'p_value': 12,          # binomial p-value column (absolute mode), lower is better
    },
}
# ============================================================================


@dataclass
class CANMessage:
    """Represents a single CAN message from any supported log format."""
    channel: int
    can_id: str
    format_flag: str
    data_length: int
    data_bytes: List[str]
    timestamp: float
    direction: str
    raw_line: str
    line_number: int

    @property
    def data_signature(self) -> str:
        """Return a string representation of the data bytes for comparison."""
        return ' '.join(self.data_bytes)

    def get_j1939_fields(self) -> Optional[Dict[str, Any]]:
        """Extract J1939 fields from the CAN message. Works for both Nexiq and Kvaser formats."""
        if len(self.data_bytes) < 8:
            return None
        try:
            payload_bytes = [int(b, 16) for b in self.data_bytes]
        except ValueError:
            return None
        can_id_int = int(self.can_id, 16) if isinstance(self.can_id, str) else self.can_id
        priority = (can_id_int >> 26) & 0x07
        pgn = (can_id_int >> 8) & 0x3FFFF
        source_address = can_id_int & 0xFF
        
        destination_address = 0xFF
        payload = self.data_bytes
        
        if self.format_flag == 'J1939':
            destination_address = payload_bytes[0] if len(payload_bytes) >= 1 else 0xFF
        else:
            destination_address = payload_bytes[0] if len(payload_bytes) >= 1 else 0xFF
        
        return {
            'pgn': pgn,
            'source_address': source_address,
            'destination_address': destination_address,
            'priority': priority,
            'payload': payload,
            'payload_hex': ' '.join(payload),
        }


@dataclass
class CandidateCommandMatch:
    """Represents a candidate command matched by aligning to fire times."""
    can_id: str
    data_signature: str
    data_length: int
    sample_timestamp: float
    sample_line: int
    coverage: float
    median_abs_delta: float
    avg_abs_delta: float
    max_abs_delta: float
    confidence: float
    p_value: float      # Binomial p-value: P(coverage >= k by chance under Poisson null)


@dataclass
class OffsetCommandMatch:
    """Represents a candidate command matched via sliding offset search."""
    can_id: str
    data_signature: str
    data_length: int
    best_offset: float   # log timestamp that aligns to video t=0
    coverage: float
    median_abs_delta: float
    avg_abs_delta: float
    max_abs_delta: float
    confidence: float
    sample_line: int


# ============================================================================
# LOG FORMAT DEFINITIONS
# Each LogFormat subclass defines a regex pattern and a field extractor
# that converts a regex match into a CANMessage. To support a new log type,
# create a new subclass and pass it to CANLogParser.
# ============================================================================

class LogFormat(ABC):
    """
    Abstract base class for log format parsers.

    Subclass this and implement `line_regex` and `_extract_fields` to
    support a new log file type. The parser will call `parse_line` for
    every line in the file.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable name for this log format."""

    @property
    @abstractmethod
    def line_regex(self) -> re.Pattern:
        """Compiled regex that must match a message line."""

    @abstractmethod
    def _extract_fields(self, match: re.Match, raw_line: str, line_num: int) -> Optional[CANMessage]:
        """
        Convert a successful regex match into a CANMessage.
        Return None if the line should be skipped despite matching.
        """

    def skip_line(self, line: str) -> bool:
        """
        Return True if this line should be ignored before regex matching.
        Override to filter non-message lines cheaply.
        """
        return False

    def parse_line(self, line: str, line_num: int) -> Optional[CANMessage]:
        """Parse one log line. Returns CANMessage or None."""
        line = line.strip()
        if not line or self.skip_line(line):
            return None
        match = self.line_regex.match(line)
        if not match:
            return None
        return self._extract_fields(match, line, line_num)


class KvaserLogFormat(LogFormat):
    """
    Parser for Kvaser CANalyzer/CANdb text log files.

    Expected line format:
        <channel> <CAN_ID> <flag> <DLC> [<byte> ...] <timestamp> [<direction>]

    Example:
        1 0CF00400 Rx 8 00 01 02 03 04 FF FF FF 1234.567890 Tx
    """

    _SKIP_FRAGMENTS = ('ErrorFrame',)

    # Groups: channel, can_id, flag, dlc, data_str, timestamp, direction
    _PATTERN = re.compile(
        r'^(\d+)'                           # channel
        r'\s+([0-9A-Fa-f]+)'               # CAN ID (hex)
        r'\s+(\w+)'                         # format flag (Rx/Tx/etc.)
        r'\s+(\d+)'                         # DLC
        r'((?:\s+[0-9A-Fa-f]{1,2})*)'     # data bytes (space-separated hex)
        r'\s+([\d.]+)'                      # timestamp
        r'(?:\s+(\w+))?'                    # optional direction
    )

    @property
    def name(self) -> str:
        return 'Kvaser'

    @property
    def line_regex(self) -> re.Pattern:
        return self._PATTERN

    def skip_line(self, line: str) -> bool:
        return any(f in line for f in self._SKIP_FRAGMENTS)

    def _extract_fields(self, match: re.Match, raw_line: str, line_num: int) -> Optional[CANMessage]:
        try:
            channel = int(match.group(1))
            can_id = match.group(2)
            format_flag = match.group(3)
            data_length = int(match.group(4))
            data_bytes = match.group(5).split() if match.group(5).strip() else []
            timestamp = float(match.group(6))
            direction = match.group(7) or ''

            if len(data_bytes) != data_length:
                return None

            return CANMessage(
                channel=channel,
                can_id=can_id,
                format_flag=format_flag,
                data_length=data_length,
                data_bytes=data_bytes,
                timestamp=timestamp,
                direction=direction,
                raw_line=raw_line,
                line_number=line_num,
            )
        except (ValueError, IndexError):
            return None


class NexiqLogFormat(LogFormat):
    """
    Parser for Diesel Laptops Nexiq adapter RP1210 J1939 log files.

    Each data line looks like:
        012332.844567 (delta)  Rx() ID = 01 Ret = 0018 Sz = 02048 Blk = 0 Data:  B0 B1 ... B17

    The leading timestamp is a large decimal float (seconds since some reference epoch,
    exact origin unknown). It is stored on each CANMessage as-is via float().
    command_fire_times in CONFIG should use the same numeric form.

    The 18-byte payload follows a Nexiq/RP1210 J1939 frame structure:
        Bytes 0-3  : 4-byte internal counter (big-endian)
        Byte  4    : Transport/echo flag
        Byte  5    : J1939 PDU Format (PF)   ─┐
        Byte  6    : J1939 PDU Specific (PS)  ├─ together form the PGN
        Byte  7    : Priority (3-bit value)  ─┘
        Byte  8    : Source Address (SA)
        Byte  9    : Destination Address (DA)
        Bytes 10-17: 8-byte J1939 data payload

    The J1939 29-bit CAN ID is reconstructed as:
        (priority << 26) | (PF << 16) | (PS << 8) | SA
    and formatted as an 8-character uppercase hex string (e.g. "0CF00003").

    """

    # Groups: ts, direction, channel_id, data_hex_str
    _PATTERN = re.compile(
        r'^(\d+\.\d+)'                      # timestamp float (large decimal, origin unknown)
        r'\s+\(\d+\.\d+\)'                 # (delta) - ignored
        r'\s+(\w+\(\))'                    # direction token: Rx(), Tx(), etc.
        r'\s+ID\s*=\s*(\d+)'              # connection/device ID
        r'.*?Data:\s+'                      # skip Ret/Sz/Blk fields
        r'((?:[0-9A-Fa-f]{2}\s*)+)'       # hex data bytes
    )

    @property
    def name(self) -> str:
        return 'Nexiq-J1939'

    @property
    def line_regex(self) -> re.Pattern:
        return self._PATTERN

    def skip_line(self, line: str) -> bool:
        # Skip non-data lines cheaply before running the full regex
        return 'Data:' not in line

    @staticmethod
    def _decode_can_id(data_bytes: List[int]) -> str:
        """
        Reconstruct a J1939 29-bit CAN ID from the Nexiq frame header bytes.
        Returns an 8-character uppercase hex string (e.g. '0CF00003').
        Requires at least 9 bytes.
        """
        if len(data_bytes) < 9:
            return 'UNKNOWN'
        pf = data_bytes[5]   # PDU Format
        ps = data_bytes[6]   # PDU Specific / Group Extension
        pri = data_bytes[7]  # Priority (0-7)
        sa = data_bytes[8]   # Source Address
        can_id_int = (pri << 26) | (pf << 16) | (ps << 8) | sa
        return f'{can_id_int:08X}'

    def _extract_fields(self, match: re.Match, raw_line: str, line_num: int) -> Optional[CANMessage]:
        try:
            ts_str = match.group(1)
            direction_token = match.group(2)          # e.g. "Rx()" or "Tx()"
            channel = int(match.group(3))
            hex_str = match.group(4).strip()

            raw_bytes = [int(b, 16) for b in hex_str.split()]

            # Need full 18-byte Nexiq frame to decode CAN ID and payload
            if len(raw_bytes) < 18:
                return None

            timestamp = float(ts_str)

            can_id = self._decode_can_id(raw_bytes)
            payload = raw_bytes[10:18]  # 8-byte J1939 data payload
            data_bytes = [f'{b:02X}' for b in payload]
            direction = direction_token.rstrip('()')  # "Rx" or "Tx"

            return CANMessage(
                channel=channel,
                can_id=can_id,
                format_flag='J1939',
                data_length=len(data_bytes),
                data_bytes=data_bytes,
                timestamp=timestamp,
                direction=direction,
                raw_line=raw_line,
                line_number=line_num,
            )
        except (ValueError, IndexError):
            return None


def detect_log_format(filename: str) -> LogFormat:
    """
    Auto-detect the log format by inspecting the first few data lines.
    Returns a KvaserLogFormat or NexiqLogFormat instance.
    """
    Nexiq = NexiqLogFormat()
    kvaser = KvaserLogFormat()
    try:
        with open(filename, 'r', errors='replace') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                if Nexiq.line_regex.match(line):
                    print(f"Auto-detected log format: {Nexiq.name}")
                    return Nexiq
                if kvaser.line_regex.match(line):
                    print(f"Auto-detected log format: {kvaser.name}")
                    return kvaser
    except FileNotFoundError:
        pass
    # Default to Kvaser if nothing matches
    print("Warning: Could not auto-detect log format; defaulting to Kvaser.")
    return KvaserLogFormat()


# ============================================================================
# ANALYZER - unchanged core logic, works with any CANMessage list
# ============================================================================

class CANDataPatternAnalyzer:
    """Core analyzer for CAN data patterns."""

    def __init__(self, messages: List[CANMessage]):
        self.messages = messages
        self._messages_by_pattern: Dict[str, List[CANMessage]] = {}
        for msg in messages:
            self._messages_by_pattern.setdefault(msg.data_signature, []).append(msg)

    def filter_by_unique_data_after(self, min_timestamp: float) -> List[CANMessage]:
        """Filter messages to only include data patterns first appearing after min_timestamp."""
        if not self.messages:
            return []
        first_occurrence = self._get_first_occurrence_times()
        valid_patterns = {
            pattern for pattern, first_time in first_occurrence.items()
            if first_time >= min_timestamp
        }
        filtered_messages = [
            msg for msg in self.messages
            if msg.data_signature in valid_patterns
        ]
        self._print_filter_stats(min_timestamp, first_occurrence, valid_patterns)
        return filtered_messages

    def find_patterns_by_occurrence_count(self, occurrence_count: int) -> List[Tuple[str, List[CANMessage]]]:
        """Return all data patterns that appear exactly occurrence_count times."""
        if occurrence_count is None or occurrence_count <= 0:
            return []
        matching_patterns: List[Tuple[str, List[CANMessage]]] = []
        for pattern, msgs in self._messages_by_pattern.items():
            if len(msgs) == occurrence_count:
                ordered_msgs = sorted(msgs, key=lambda m: m.timestamp)
                matching_patterns.append((pattern, ordered_msgs))
        return matching_patterns

    def _get_first_occurrence_times(self) -> Dict[str, float]:
        first_occurrence = {}
        for msg in self.messages:
            pattern = msg.data_signature
            if pattern not in first_occurrence:
                first_occurrence[pattern] = msg.timestamp
        return first_occurrence

    def _print_filter_stats(self, min_timestamp: float,
                            first_occurrence: Dict[str, float],
                            valid_patterns: Set[str]) -> None:
        print(f"\nFiltering by unique data first appearance after {min_timestamp:.6f}s:")
        print(f"  Total unique data patterns: {len(first_occurrence)}")
        print(f"  Data patterns appearing after threshold: {len(valid_patterns)}")
        print(f"  Messages before filtering: {len(self.messages)}")
        print(f"  Messages after filtering: {len([m for m in self.messages if m.data_signature in valid_patterns])}")
        if valid_patterns:
            print(f"  Sample valid data patterns:")
            for i, pattern in enumerate(sorted(valid_patterns)[:5]):
                print(f"    {i+1}: [{pattern}]")
            if len(valid_patterns) > 5:
                print(f"    ... and {len(valid_patterns) - 5} more")

    def dump_data_patterns(self, sort_by: str = 'first_time') -> None:
        """Dump all unique data patterns with statistics."""
        if not self.messages:
            print("No messages to analyze.")
            return
        pattern_stats = self._collect_pattern_statistics()
        sorted_patterns = self._sort_patterns(pattern_stats, sort_by)
        self._print_pattern_analysis(sorted_patterns, sort_by)

    def _collect_pattern_statistics(self) -> Dict[str, Dict[str, Any]]:
        pattern_stats = {}
        for msg in self.messages:
            pattern = msg.data_signature
            if pattern not in pattern_stats:
                pattern_stats[pattern] = {
                    'count': 0,
                    'first_time': msg.timestamp,
                    'last_time': msg.timestamp,
                    'can_ids': set(),
                    'first_msg': msg,
                }
            stats = pattern_stats[pattern]
            stats['count'] += 1
            stats['first_time'] = min(stats['first_time'], msg.timestamp)
            stats['last_time'] = max(stats['last_time'], msg.timestamp)
            stats['can_ids'].add(msg.can_id)
        return pattern_stats

    def _sort_patterns(self, pattern_stats: Dict[str, Dict[str, Any]],
                       sort_by: str) -> List[Tuple[str, Dict[str, Any]]]:
        if sort_by == 'count':
            return sorted(pattern_stats.items(), key=lambda x: x[1]['count'], reverse=True)
        elif sort_by == 'pattern':
            return sorted(pattern_stats.items())
        elif sort_by == 'last_time':
            return sorted(pattern_stats.items(), key=lambda x: x[1]['last_time'])
        else:
            return sorted(pattern_stats.items(), key=lambda x: x[1]['first_time'])

    def _print_pattern_analysis(self, sorted_patterns: List[Tuple[str, Dict[str, Any]]],
                                sort_by: str) -> None:
        print(f"\n=== Data Pattern Analysis (sorted by {sort_by}) ===")
        print(f"{'Data Pattern':<30} {'Count':<8} {'First Time':<12} {'Last Time':<12} {'Duration':<10} {'CAN IDs'}")
        print("-" * 100)
        for pattern, stats in sorted_patterns:
            duration = stats['last_time'] - stats['first_time']
            can_ids_str = ','.join(sorted(stats['can_ids']))[:20]
            if len(can_ids_str) >= 20:
                can_ids_str += "..."
            display_pattern = pattern[:28] + ".." if len(pattern) > 30 else pattern
            print(f"{display_pattern:<30} {stats['count']:<8} "
                  f"{stats['first_time']:<12.6f} {stats['last_time']:<12.6f} "
                  f"{duration:<10.3f} {can_ids_str}")
        print(f"\nTotal unique data patterns: {len(sorted_patterns)}")
        print(f"Total messages: {sum(stats['count'] for _, stats in sorted_patterns)}")

    def get_unique_data_patterns(self) -> List[str]:
        return list(set(msg.data_signature for msg in self.messages))

    def print_data_pattern_messages(self, target_pattern: str,
                                    max_messages: int = None,
                                    show_hex: bool = True) -> None:
        matching_messages = self.get_messages_by_data_pattern(target_pattern)
        if not matching_messages:
            self._print_no_matching_patterns(target_pattern)
            return
        self._analyze_data_pattern(matching_messages, target_pattern)
        self._print_matching_messages(matching_messages, target_pattern, max_messages, show_hex)

    def _print_no_matching_patterns(self, target_pattern: str) -> None:
        print(f"No messages found for data pattern: [{target_pattern}]")
        available_patterns = sorted(self.get_unique_data_patterns())
        print(f"Available patterns (first 5): {available_patterns[:5]}")

    def _print_matching_messages(self, messages: List[CANMessage],
                                 target_pattern: str,
                                 max_messages: int,
                                 show_hex: bool) -> None:
        if max_messages and len(messages) > max_messages:
            print(f"Showing first {max_messages} of {len(messages)} messages for pattern: [{target_pattern}]")
            display_messages = messages[:max_messages]
        else:
            print(f"All {len(messages)} messages for pattern: [{target_pattern}]")
            display_messages = messages
        print(f"{'#':<6} {'CAN ID':<12} {'Timestamp':<12} {'DL':<3} {'Data Bytes':<30} {'Line#':<6}")
        print("-" * 75)
        for i, msg in enumerate(display_messages, 1):
            data_str = self._format_data_bytes(msg.data_bytes, show_hex)
            print(f"{i:<6} {msg.can_id:<12} {msg.timestamp:<12.6f} {msg.data_length:<3} {data_str:<30} {msg.line_number:<6}")

    def _format_data_bytes(self, data_bytes: List[str], show_hex: bool) -> str:
        if show_hex:
            return ' '.join(f"{byte:>2}" for byte in data_bytes)
        try:
            return ' '.join(f"{int(byte, 16):>3}" for byte in data_bytes)
        except ValueError:
            return ' '.join(f"{byte:>3}" for byte in data_bytes)

    def _analyze_data_pattern(self, messages: List[CANMessage], pattern: str) -> None:
        print(f"\n=== Pattern Analysis for [{pattern}] ===")
        first_msg = messages[0]
        last_msg = messages[-1]
        total_duration = last_msg.timestamp - first_msg.timestamp
        if len(messages) > 1:
            intervals = self._calculate_intervals(messages)
            avg_interval = sum(intervals) / len(intervals)
            min_interval = min(intervals)
            max_interval = max(intervals)
            print(f"Timing: {total_duration:.3f}s total, avg interval: {avg_interval:.6f}s, "
                  f"range: {min_interval:.6f}s - {max_interval:.6f}s")
        can_ids = set(msg.can_id for msg in messages)
        print(f"Used by {len(can_ids)} different CAN ID(s): {sorted(can_ids)}")
        channels = set(msg.channel for msg in messages)
        print(f"Seen on channel(s): {sorted(channels)}")

    def _calculate_intervals(self, messages: List[CANMessage]) -> List[float]:
        intervals = []
        for i in range(1, len(messages)):
            intervals.append(messages[i].timestamp - messages[i - 1].timestamp)
        return intervals

    def get_messages_by_data_pattern(self, target_pattern: str) -> List[CANMessage]:
        return [msg for msg in self.messages if msg.data_signature == target_pattern]

    def find_similar_patterns(self, reference_pattern: str,
                              max_differences: int = 1) -> List[Tuple[str, int]]:
        ref_bytes = reference_pattern.split()
        similar_patterns = []
        for msg in self.messages:
            msg_bytes = msg.data_bytes
            if len(msg_bytes) != len(ref_bytes):
                continue
            differences = sum(1 for a, b in zip(ref_bytes, msg_bytes) if a != b)
            if 0 < differences <= max_differences:
                pattern = msg.data_signature
                if pattern not in [p[0] for p in similar_patterns]:
                    similar_patterns.append((pattern, differences))
        similar_patterns.sort(key=lambda x: x[1])
        return similar_patterns

    def find_command_candidates(
        self,
        fire_times: List[float],
        search_radius: float = 0.75,
        min_coverage: float = 0.5,
        max_candidates: int = 15,
        expected_occurrence_count: Optional[int] = None,
    ) -> List[CandidateCommandMatch]:
        """
        Find candidate command messages by aligning data patterns to fire times.
        Only considers patterns where ALL occurrences fall within search windows.
        """
        if not fire_times or not self.messages:
            return []

        target_times = sorted(fire_times)
        occurrence_filter = expected_occurrence_count if expected_occurrence_count and expected_occurrence_count > 0 else None

        fire_time_windows = set()
        for ft in target_times:
            for msg in self.messages:
                if abs(msg.timestamp - ft) <= search_radius:
                    fire_time_windows.add(msg.timestamp)

        # Pre-compute log duration once for the Poisson null background rate
        all_ts = [m.timestamp for m in self.messages]
        _T_total = (max(all_ts) - min(all_ts)) if len(all_ts) > 1 else 1.0
        _T_total = max(_T_total, 1e-9)  # guard against zero-duration logs

        candidates: List[CandidateCommandMatch] = []

        for pattern, msgs in self._messages_by_pattern.items():
            msgs_sorted = sorted(msgs, key=lambda m: m.timestamp)
            if occurrence_filter and len(msgs_sorted) != occurrence_filter:
                continue
            can_ids = {m.can_id for m in msgs_sorted}
            can_id = max(can_ids, key=lambda cid: sum(1 for m in msgs_sorted if m.can_id == cid))

            all_in_window = all(msg.timestamp in fire_time_windows for msg in msgs_sorted)
            if not all_in_window:
                continue

            ts = [m.timestamp for m in msgs_sorted]
            match_deltas: List[float] = []
            matched_timestamps: List[float] = []
            for ft in target_times:
                nearest_delta = self._nearest_delta(ts, ft)
                if nearest_delta is None or abs(nearest_delta) > search_radius:
                    continue
                match_deltas.append(nearest_delta)
                matched_timestamps.append(ft + nearest_delta)

            coverage = len(match_deltas) / len(target_times) if target_times else 0.0
            if coverage < min_coverage:
                continue

            abs_deltas = [abs(d) for d in match_deltas]
            median_abs = statistics.median(abs_deltas) if abs_deltas else float('inf')
            avg_abs = statistics.mean(abs_deltas) if abs_deltas else float('inf')
            max_abs = max(abs_deltas) if abs_deltas else float('inf')

            tightness = 1.0 / (1.0 + median_abs) if median_abs != float('inf') else 0.0
            confidence = 0.7 * coverage + 0.3 * tightness

            # --- Binomial p-value ---
            # Under H0: pattern occurs as Poisson process at background rate.
            # p_null = prob that at least one occurrence falls in a ±radius window
            # by chance. P(X >= k) tested against Binomial(n_fire_times, p_null).
            _lambda = len(msgs_sorted) / _T_total          # background rate (Hz)
            _p_null = 1.0 - math.exp(-_lambda * 2.0 * search_radius)
            _p_null = max(0.0, min(1.0, _p_null))
            p_value = self._binomial_pvalue(len(match_deltas), len(target_times), _p_null)

            sample_timestamp = matched_timestamps[0] if matched_timestamps else msgs_sorted[0].timestamp
            sample_line = next(
                (m.line_number for m in msgs_sorted if abs(m.timestamp - sample_timestamp) < 0.001),
                msgs_sorted[0].line_number,
            )

            candidates.append(
                CandidateCommandMatch(
                    can_id=can_id,
                    data_signature=pattern,
                    data_length=msgs_sorted[0].data_length,
                    sample_timestamp=sample_timestamp,
                    sample_line=sample_line,
                    coverage=coverage,
                    median_abs_delta=median_abs,
                    avg_abs_delta=avg_abs,
                    max_abs_delta=max_abs,
                    confidence=confidence,
                    p_value=p_value,
                )
            )

        # Sort by p-value ascending: most statistically significant first.
        # Ties broken by confidence descending (heuristic fallback).
        candidates.sort(key=lambda c: (c.p_value, -c.confidence))
        return candidates[:max_candidates]

    def find_command_candidates_offset_search(
        self,
        relative_fire_times: List[float],
        search_radius: float = 1.0,
        min_coverage: float = 0.5,
        max_candidates: int = 15,
        max_occurrences_per_slot: float = 2.0,
    ) -> List[OffsetCommandMatch]:
        """
        Find candidate command messages using a sliding timestamp offset search.

        For each data pattern, generates candidate log offsets by computing
        T = occurrence_timestamp - relative_fire_time for every (occurrence, fire_time)
        pair. Deduplicates nearby offsets, then scores each by coverage and timing
        tightness. Patterns with too many occurrences inside the session window are
        skipped as likely high-frequency background noise.

        Args:
            relative_fire_times: Command fire times measured from video t=0 (seconds).
            search_radius: ±seconds tolerance when matching occurrences to fire times.
            min_coverage: Minimum fraction of fire_times that must match (0.0-1.0).
            max_candidates: Maximum number of results to return.
            max_occurrences_per_slot: Patterns with more than
                (len(relative_fire_times) * max_occurrences_per_slot) occurrences inside
                the session window are skipped as background noise.

        Returns:
            List of OffsetCommandMatch sorted by confidence descending.
        """
        if not relative_fire_times or not self.messages:
            return []

        rel_times = sorted(relative_fire_times)
        n_fire_times = len(rel_times)
        max_allowed_in_window = n_fire_times * max_occurrences_per_slot

        candidates: List[OffsetCommandMatch] = []

        for pattern, msgs in self._messages_by_pattern.items():
            msgs_sorted = sorted(msgs, key=lambda m: m.timestamp)
            ts_list = [m.timestamp for m in msgs_sorted]

            # Generate all candidate offsets: T = occurrence_ts - relative_fire_time
            raw_offsets: List[float] = []
            for t_occur in ts_list:
                for t_rel in rel_times:
                    raw_offsets.append(t_occur - t_rel)

            deduped_offsets = self._deduplicate_offsets(raw_offsets, search_radius)

            best_match: Optional[OffsetCommandMatch] = None
            best_confidence = -1.0

            for offset in deduped_offsets:
                # Filter high-frequency background: count occurrences within the
                # session window [offset+rel_times[0], offset+rel_times[-1]]
                session_start = offset + rel_times[0]
                session_end = offset + rel_times[-1]
                in_window = sum(
                    1 for t in ts_list
                    if session_start - search_radius <= t <= session_end + search_radius
                )
                if in_window > max_allowed_in_window:
                    continue

                # Score this offset
                shifted_times = [t_rel + offset for t_rel in rel_times]
                match_deltas: List[float] = []
                for ft in shifted_times:
                    delta = self._nearest_delta(ts_list, ft)
                    if delta is None or abs(delta) > search_radius:
                        continue
                    match_deltas.append(delta)

                coverage = len(match_deltas) / n_fire_times if n_fire_times else 0.0
                if coverage < min_coverage:
                    continue

                abs_deltas = [abs(d) for d in match_deltas]
                median_abs = statistics.median(abs_deltas) if abs_deltas else float('inf')
                avg_abs = statistics.mean(abs_deltas) if abs_deltas else float('inf')
                max_abs = max(abs_deltas) if abs_deltas else float('inf')

                tightness = 1.0 / (1.0 + median_abs) if median_abs != float('inf') else 0.0
                confidence = 0.7 * coverage + 0.3 * tightness

                if confidence > best_confidence:
                    best_confidence = confidence
                    can_ids = {m.can_id for m in msgs_sorted}
                    can_id = max(can_ids, key=lambda cid: sum(1 for m in msgs_sorted if m.can_id == cid))
                    best_match = OffsetCommandMatch(
                        can_id=can_id,
                        data_signature=pattern,
                        data_length=msgs_sorted[0].data_length,
                        best_offset=offset,
                        coverage=coverage,
                        median_abs_delta=median_abs,
                        avg_abs_delta=avg_abs,
                        max_abs_delta=max_abs,
                        confidence=confidence,
                        sample_line=msgs_sorted[0].line_number,
                    )

            if best_match is not None:
                candidates.append(best_match)

        candidates.sort(key=lambda c: c.confidence, reverse=True)
        return candidates[:max_candidates]

    @staticmethod
    def _deduplicate_offsets(offsets: List[float], radius: float) -> List[float]:
        """
        Collapse candidate offsets that are within radius of each other.
        Keeps the smallest representative from each cluster.
        """
        if not offsets:
            return []
        sorted_offsets = sorted(offsets)
        deduped = [sorted_offsets[0]]
        for o in sorted_offsets[1:]:
            if o - deduped[-1] > radius:
                deduped.append(o)
        return deduped

    @staticmethod
    def _nearest_delta(sorted_ts: List[float], target: float) -> Optional[float]:
        if not sorted_ts:
            return None
        lo, hi = 0, len(sorted_ts) - 1
        while lo < hi:
            mid = (lo + hi) // 2
            if sorted_ts[mid] < target:
                lo = mid + 1
            else:
                hi = mid
        candidates = []
        if lo < len(sorted_ts):
            candidates.append(sorted_ts[lo])
        if lo > 0:
            candidates.append(sorted_ts[lo - 1])
        nearest = min(candidates, key=lambda x: abs(x - target))
        return nearest - target

    @staticmethod
    def _binomial_pvalue(k: int, n: int, p: float) -> float:
        """
        One-tailed binomial p-value: P(X >= k) where X ~ Binomial(n, p).

        Computes the probability that at least k out of n independent trials
        succeed, each with probability p. This is the probability of observing
        the measured coverage (or higher) purely by chance under the null
        hypothesis that the pattern occurs at a uniform background rate.

        Uses log-space arithmetic via math.lgamma to avoid overflow for large n.

        Args:
            k: Number of fire-time slots that had a matching occurrence.
            n: Total number of fire-time slots.
            p: Null probability that a single slot is matched by chance,
               computed as 1 - exp(-lambda * 2 * search_radius), where
               lambda is the pattern's background occurrence rate (Hz).

        Returns:
            p-value in [0, 1]. Values near 0 indicate the coverage is
            unlikely under the null (good match); values near 1 indicate
            the coverage is consistent with random noise.
        """
        if k <= 0:
            return 1.0
        if k > n:
            return 0.0
        if p <= 0.0:
            return 0.0
        if p >= 1.0:
            return 1.0
        log_p = math.log(p)
        log_1mp = math.log(1.0 - p)
        total = 0.0
        for j in range(k, n + 1):
            log_prob = (
                math.lgamma(n + 1)
                - math.lgamma(j + 1)
                - math.lgamma(n - j + 1)
                + j * log_p
                + (n - j) * log_1mp
            )
            total += math.exp(log_prob)
        return min(total, 1.0)


# ============================================================================
# PARSER - now format-agnostic via the LogFormat abstraction
# ============================================================================

class CANLogParser:
    """
    Format-agnostic CAN log parser.

    Pass a LogFormat instance to __init__ to control which log type is parsed.
    If no format is provided, auto-detection is attempted when parse_file is called.
    """

    def __init__(self, log_format: Optional[LogFormat] = None):
        self.log_format = log_format
        self.messages: List[CANMessage] = []

    def parse_file(self, filename: str) -> None:
        """Parse an entire CAN log file using the configured LogFormat."""
        self.messages = []

        fmt = self.log_format
        if fmt is None:
            fmt = detect_log_format(filename)
            self.log_format = fmt

        # Reset stateful formats (e.g. Nexiq timestamp normalisation)
        if hasattr(fmt, 'reset'):
            fmt.reset()

        skipped = 0
        parse_errors = 0

        try:
            with open(filename, 'r', errors='replace') as f:
                for line_num, line in enumerate(f, 1):
                    try:
                        message = fmt.parse_line(line, line_num)
                    except Exception as exc:
                        parse_errors += 1
                        if parse_errors <= 5:
                            print(f"Warning: parse error on line {line_num}: {exc}")
                        continue

                    if message:
                        self.messages.append(message)
                    else:
                        skipped += 1

            print(f"[{fmt.name}] Parsed {len(self.messages)} messages from '{filename}'")
            if parse_errors:
                print(f"  {parse_errors} lines raised parse errors")

        except FileNotFoundError:
            print(f"Error: File '{filename}' not found.")
        except Exception as exc:
            print(f"Error reading '{filename}': {exc}")

    def get_messages(self) -> List[CANMessage]:
        return self.messages

    def get_message_count(self) -> int:
        return len(self.messages)

    def create_analyzer(self) -> 'CANDataPatternAnalyzer':
        return CANDataPatternAnalyzer(self.messages)

    def print_summary(self) -> None:
        if not self.messages:
            print("No messages parsed yet.")
            return

        fmt_name = self.log_format.name if self.log_format else 'unknown'
        print(f"\n=== CAN Log Summary [{fmt_name}] ===")
        print(f"Total messages: {len(self.messages)}")
        print(f"Time range: {self.messages[0].timestamp:.6f} - {self.messages[-1].timestamp:.6f}")

        unique_patterns = set(msg.data_signature for msg in self.messages)
        print(f"Unique data patterns: {len(unique_patterns)}")

        unique_ids = set(msg.can_id for msg in self.messages)
        print(f"Unique CAN IDs: {len(unique_ids)}")

        channels: Dict[int, int] = {}
        for msg in self.messages:
            channels[msg.channel] = channels.get(msg.channel, 0) + 1
        print(f"Messages by channel: {dict(sorted(channels.items()))}")

        data_lengths: Dict[int, int] = {}
        for msg in self.messages:
            data_lengths[msg.data_length] = data_lengths.get(msg.data_length, 0) + 1
        print(f"Messages by data length: {dict(sorted(data_lengths.items()))}")

        print(f"\nFirst few messages:")
        for i, msg in enumerate(self.messages[:5]):
            data_str = ' '.join(msg.data_bytes)
            print(f"  {i+1}: CH{msg.channel} {msg.can_id} DL:{msg.data_length} [{data_str}] @ {msg.timestamp:.6f}")


# ============================================================================
# OUTPUT / CONVENIENCE HELPERS
# ============================================================================

def print_command_candidates(results: List[CandidateCommandMatch], config: Dict = None) -> None:
    """Pretty-print candidate command matches using configuration settings."""
    if config is None:
        config = CONFIG

    if not results:
        print(f"No candidate {config['command_name']} patterns matched the provided fire times.")
        return

    p = config['pattern_display_width']
    d = config['delta_precision']
    c = config['confidence_precision']
    w = config['table_column_widths']

    def _fmt_pvalue(v: float) -> str:
        """Format a p-value: scientific notation below 0.001, fixed otherwise."""
        if v < 0.001:
            return f"{v:.2e}"
        return f"{v:.4f}"

    print(f"\n=== Candidate {config['command_name']} Commands ===")
    print(f"{'Rank':<{w['rank']}} {'CAN ID':<{w['can_id']}} {'Data Pattern':<{w['pattern']}} "
          f"{'Coverage':<{w['coverage']}} {'Med |Δ|':<{w['median_delta']}} {'Avg |Δ|':<{w['avg_delta']}} "
          f"{'Max |Δ|':<{w['max_delta']}} {'P(chance)':<{w['p_value']}} {'Confidence':<{w['confidence']}}")
    _ABS_COLS = ('rank', 'can_id', 'pattern', 'coverage', 'median_delta', 'avg_delta', 'max_delta', 'p_value', 'confidence')
    print("-" * (sum(w[k] for k in _ABS_COLS) + 9))

    for idx, result in enumerate(results, 1):
        med_str = f"{result.median_abs_delta:.{d}f}s" if result.median_abs_delta != float('inf') else "N/A"
        avg_str = f"{result.avg_abs_delta:.{d}f}s" if result.avg_abs_delta != float('inf') else "N/A"
        max_str = f"{result.max_abs_delta:.{d}f}s" if result.max_abs_delta != float('inf') else "N/A"
        pattern_str = result.data_signature[:p - 2] + ".." if len(result.data_signature) > p else result.data_signature
        p_str = _fmt_pvalue(result.p_value)

        print(
            f"{idx:<{w['rank']}} {result.can_id:<{w['can_id']}} {pattern_str:<{w['pattern']}} "
            f"{result.coverage:<{w['coverage']}.2f} {med_str:<{w['median_delta']}} {avg_str:<{w['avg_delta']}} "
            f"{max_str:<{w['max_delta']}} {p_str:<{w['p_value']}} {result.confidence:<{w['confidence']}.{c}f}"
        )
        ts_fmt = f"{config['timestamp_precision']}"
        print(f"       └─ Sample: ts={result.sample_timestamp:.{ts_fmt}f}, line={result.sample_line}, data_length={result.data_length}")


def print_offset_candidates(results: List[OffsetCommandMatch], config: Dict = None) -> None:
    """Pretty-print offset-search command match results."""
    if config is None:
        config = CONFIG

    if not results:
        print(f"No candidate {config['command_name']} patterns matched via offset search.")
        return

    p = config['pattern_display_width']
    d = config['delta_precision']
    c = config['confidence_precision']
    w = config['table_column_widths']
    ts_fmt = config['timestamp_precision']

    _OFF_COLS = ('rank', 'can_id', 'pattern', 'coverage', 'median_delta', 'avg_delta', 'max_delta', 'offset', 'confidence')

    print(f"\n=== Candidate {config['command_name']} Commands (Offset Search) ===")
    print(f"{'Rank':<{w['rank']}} {'CAN ID':<{w['can_id']}} {'Data Pattern':<{w['pattern']}} "
          f"{'Coverage':<{w['coverage']}} {'Med |Δ|':<{w['median_delta']}} {'Avg |Δ|':<{w['avg_delta']}} "
          f"{'Max |Δ|':<{w['max_delta']}} {'Best Offset':<{w['offset']}} {'Confidence':<{w['confidence']}}")
    print("-" * (sum(w[k] for k in _OFF_COLS) + 9))

    for idx, result in enumerate(results, 1):
        med_str = f"{result.median_abs_delta:.{d}f}s" if result.median_abs_delta != float('inf') else "N/A"
        avg_str = f"{result.avg_abs_delta:.{d}f}s" if result.avg_abs_delta != float('inf') else "N/A"
        max_str = f"{result.max_abs_delta:.{d}f}s" if result.max_abs_delta != float('inf') else "N/A"
        pattern_str = result.data_signature[:p - 2] + ".." if len(result.data_signature) > p else result.data_signature
        offset_str = f"{result.best_offset:.{ts_fmt}f}"

        print(
            f"{idx:<{w['rank']}} {result.can_id:<{w['can_id']}} {pattern_str:<{w['pattern']}} "
            f"{result.coverage:<{w['coverage']}.2f} {med_str:<{w['median_delta']}} {avg_str:<{w['avg_delta']}} "
            f"{max_str:<{w['max_delta']}} {offset_str:<{w['offset']}} {result.confidence:<{w['confidence']}.{c}f}"
        )
        print(f"       └─ line={result.sample_line}, data_length={result.data_length}")


def find_command_from_config(config: Dict = None) -> List[CandidateCommandMatch]:
    """Convenience function to run command detection using CONFIG settings."""
    if config is None:
        config = CONFIG

    log_format = config.get('log_format')
    parser = CANLogParser(log_format=log_format)

    log_path = config['full_log_path']() if callable(config.get('full_log_path')) else config.get('full_log_path')
    parser.parse_file(log_path)

    if config['print_log_summary']:
        parser.print_summary()

    analyzer = parser.create_analyzer()
    expected_occurrences = config.get('expected_occurrence_count')
    if callable(expected_occurrences):
        try:
            expected_occurrences = expected_occurrences(config)
        except TypeError:
            expected_occurrences = expected_occurrences()

    pattern_matches: List[Tuple[str, List[CANMessage]]] = []
    if isinstance(expected_occurrences, int) and expected_occurrences > 0:
        pattern_matches = analyzer.find_patterns_by_occurrence_count(expected_occurrences)
        if config.get('print_verbose'):
            print(f"\nFound {len(pattern_matches)} data pattern(s) occurring exactly {expected_occurrences} times.")
            preview = min(5, len(pattern_matches))
            for i in range(preview):
                pattern, msgs = pattern_matches[i]
                can_ids = sorted({m.can_id for m in msgs})
                first_ts = msgs[0].timestamp if msgs else 0.0
                print(f"    {i+1}. [{pattern}] via CAN ID(s) {can_ids} (first ts {first_ts:.6f})")
            if len(pattern_matches) > preview:
                print(f"    ... and {len(pattern_matches) - preview} more")

    if config['print_verbose']:
        print(f"\nSearching for {config['command_name']} command...")
        print(f"Fire times: {config['command_fire_times']}")
        print(f"Search radius: ±{config['search_radius']}s, Min coverage: {config['min_coverage']:.0%}")
        if isinstance(expected_occurrences, int) and expected_occurrences > 0:
            print(f"Expected occurrence count: {expected_occurrences}")

    candidates = analyzer.find_command_candidates(
        fire_times=config['command_fire_times'],
        search_radius=config['search_radius'],
        min_coverage=config['min_coverage'],
        max_candidates=config['max_candidates'],
        expected_occurrence_count=expected_occurrences if isinstance(expected_occurrences, int) and expected_occurrences > 0 else None,
    )

    return candidates


def find_offset_command_from_config(config: Dict = None) -> List[OffsetCommandMatch]:
    """Convenience function to run offset-search command detection using CONFIG settings."""
    if config is None:
        config = CONFIG

    log_format = config.get('log_format')
    parser = CANLogParser(log_format=log_format)

    log_path = config['full_log_path']() if callable(config.get('full_log_path')) else config.get('full_log_path')
    parser.parse_file(log_path)

    if config['print_log_summary']:
        parser.print_summary()

    analyzer = parser.create_analyzer()
    rel_times = config['relative_fire_times']

    if config['print_verbose']:
        print(f"\nSearching for {config['command_name']} command (offset search)...")
        print(f"Relative fire times: {rel_times}")
        print(f"Search radius: ±{config['search_radius']}s, Min coverage: {config['min_coverage']:.0%}")
        print(f"Max occurrences per slot: {config['max_occurrences_per_slot']}")

    return analyzer.find_command_candidates_offset_search(
        relative_fire_times=rel_times,
        search_radius=config['search_radius'],
        min_coverage=config['min_coverage'],
        max_candidates=config['max_candidates'],
        max_occurrences_per_slot=config['max_occurrences_per_slot'],
    )


# ============================================================================
# MULTI-LOG ANALYSIS - Cross-log similarity detection
# ============================================================================

@dataclass
class PerFileCandidate:
    """Represents a unique-per-file candidate command."""
    filename: str
    can_id: str
    data_signature: str
    timestamp: float
    line_number: int
    j1939_fields: Optional[Dict[str, Any]]
    occurrence_count: int


@dataclass
class CrossLogMatch:
    """Represents a matched command across multiple logs."""
    pgn: int
    source_address: int
    destination_address: int
    candidates: List[PerFileCandidate]
    similarity_score: float
    payload_variance: float


def collect_log_files(paths: List[str]) -> List[str]:
    """Collect all log files from given paths (files or directories)."""
    log_files = []
    for path in paths:
        path = path.strip()
        if os.path.isfile(path):
            log_files.append(path)
        elif os.path.isdir(path):
            for entry in os.listdir(path):
                full_path = os.path.join(path, entry)
                if os.path.isfile(full_path) and entry.lower().endswith(('.log', '.txt')):
                    log_files.append(full_path)
    return sorted(log_files)


def compute_payload_similarity(payload1: List[str], payload2: List[str]) -> float:
    """Compute similarity between two 8-byte payloads (0.0 to 1.0)."""
    if len(payload1) != len(payload2):
        return 0.0
    exact_matches = sum(1 for a, b in zip(payload1, payload2) if a == b)
    exact_ratio = exact_matches / len(payload1)
    numeric_distances = []
    for a, b in zip(payload1, payload2):
        try:
            val_a, val_b = int(a, 16), int(b, 16)
            dist = abs(val_a - val_b) / 255.0
            numeric_distances.append(1.0 - dist)
        except ValueError:
            numeric_distances.append(1.0 if a == b else 0.0)
    numeric_similarity = sum(numeric_distances) / len(numeric_distances) if numeric_distances else 0.0
    return (exact_ratio * 0.6) + (numeric_similarity * 0.4)


def compute_candidate_similarity(candidates: List[PerFileCandidate]) -> Tuple[float, float]:
    """Compute similarity score and variance for a group of candidates."""
    if len(candidates) < 2:
        return 1.0, 0.0
    payloads = [c.j1939_fields['payload'] for c in candidates if c.j1939_fields and 'payload' in c.j1939_fields]
    if not payloads:
        return 0.0, float('inf')
    similarity_scores = []
    for i, p1 in enumerate(payloads):
        for p2 in payloads[i+1:]:
            similarity_scores.append(compute_payload_similarity(p1, p2))
    avg_similarity = sum(similarity_scores) / len(similarity_scores) if similarity_scores else 0.0
    byte_variances = []
    for byte_idx in range(8):
        try:
            byte_values = [int(p[byte_idx], 16) for p in payloads if byte_idx < len(p)]
            if len(byte_values) > 1:
                mean = sum(byte_values) / len(byte_values)
                variance = sum((x - mean) ** 2 for x in byte_values) / len(byte_values)
                byte_variances.append(variance)
        except (ValueError, IndexError):
            pass
    return avg_similarity, sum(byte_variances)


def analyze_multi_log(files: List[str], config: Dict = None) -> Dict[str, Any]:
    """
    Analyze multiple log files to find candidate commands that:
      - Occur exactly once per file (i.e. one confirmed firing per capture)
      - Appear in at least 2 different files (same PGN / SA / DA)
      - Have similar-but-not-identical payloads across files
    """
    if config is None:
        config = CONFIG

    # Map from filename -> list of single-occurrence candidates
    per_file_candidates: List[PerFileCandidate] = []
    issues: List[Dict[str, Any]] = []

    for filepath in files:
        filename = os.path.basename(filepath)
        try:
            parser = CANLogParser(log_format=config.get('log_format'))
            parser.parse_file(filepath)
        except Exception as e:
            issues.append({'file': filename, 'type': 'error', 'message': f'Parse error: {str(e)}'})
            continue
        if not parser.messages:
            issues.append({'file': filename, 'type': 'error', 'message': 'No messages parsed'})
            continue

        analyzer = parser.create_analyzer()
        # Collect every pattern that fires exactly once in this file.
        # Each one is a plausible candidate for the unknown target command.
        patterns_exactly_one = analyzer.find_patterns_by_occurrence_count(1)
        if not patterns_exactly_one:
            issues.append({'file': filename, 'type': 'warning', 'message': 'No patterns occurring exactly once'})
            continue

        print(f"  {filename}: {len(patterns_exactly_one)} single-occurrence pattern(s)")
        for pattern, msgs in patterns_exactly_one:
            msg = msgs[0]
            j1939 = msg.get_j1939_fields()
            per_file_candidates.append(PerFileCandidate(
                filename=filename, can_id=msg.can_id, data_signature=pattern,
                timestamp=msg.timestamp, line_number=msg.line_number,
                j1939_fields=j1939, occurrence_count=1
            ))

    # Group by (PGN, SA, DA) — the fields that must be identical across logs for
    # the same command. Within each group, candidates from different files are
    # cross-log matches; candidates from the same file are ignored for scoring.
    grouped_by_key: Dict[Tuple, Dict[str, List[PerFileCandidate]]] = {}
    for cand in per_file_candidates:
        if not cand.j1939_fields:
            continue
        key = (
            cand.j1939_fields.get('pgn', 0),
            cand.j1939_fields.get('source_address', 0),
            cand.j1939_fields.get('destination_address', 0),
        )
        grouped_by_key.setdefault(key, {}).setdefault(cand.filename, []).append(cand)

    cross_log_matches: List[CrossLogMatch] = []
    for key, by_file in grouped_by_key.items():
        # Must appear in at least 2 different files
        if len(by_file) < 2:
            continue

        pgn, sa, da = key

        # Take one representative candidate per file (the only one, in normal use)
        representative: List[PerFileCandidate] = [cands[0] for cands in by_file.values()]

        similarity_score, payload_variance = compute_candidate_similarity(representative)
        cross_log_matches.append(CrossLogMatch(
            pgn=pgn, source_address=sa, destination_address=da,
            candidates=representative,
            similarity_score=similarity_score,
            payload_variance=payload_variance,
        ))

    cross_log_matches.sort(key=lambda m: (-m.similarity_score, m.payload_variance))
    return {
        'per_file_candidates': per_file_candidates,
        'cross_log_matches': cross_log_matches,
        'issues': issues,
        'files_processed': len(files),
        'files_with_candidates': len(set(c.filename for c in per_file_candidates)),
    }


def print_multi_log_results(results: Dict[str, Any], config: Dict = None) -> None:
    """Print human-readable multi-log analysis results."""
    if config is None:
        config = CONFIG
    max_results = config.get('max_cross_log_results', 20)
    print("\n" + "=" * 80)
    print("MULTI-LOG ANALYSIS RESULTS")
    print("=" * 80)
    files_processed = results.get('files_processed', 0)
    files_with_candidates = results.get('files_with_candidates', 0)
    issues = results.get('issues', [])
    print(f"\nSummary: Files processed: {files_processed}, Files with candidates: {files_with_candidates}, Issues: {len(issues)}")
    if issues:
        print("\nIssues:")
        for issue in issues:
            print(f"  [{issue['type'].upper()}] {issue['file']}: {issue['message']}")
    cross_log_matches = results.get('cross_log_matches', [])
    if not cross_log_matches:
        print("\nNo cross-log matches found (need 2+ files with same PGN/SA/DA).")
        return
    cross_log_matches = cross_log_matches[:max_results]
    print(f"\n{'=' * 80}\nCROSS-LOG MATCHES (ranked by similarity, showing top {len(cross_log_matches)})\n{'=' * 80}")
    for rank, match in enumerate(cross_log_matches, 1):
        print(f"\n--- Rank #{rank} ---")
        print(f"  PGN: 0x{match.pgn:04X} ({match.pgn}), Source: 0x{match.source_address:02X}, Dest: 0x{match.destination_address:02X}")
        print(f"  Similarity: {match.similarity_score:.4f}, Variance: {match.payload_variance:.2f}, Files: {len(match.candidates)}")
        for cand in match.candidates:
            payload_hex = cand.j1939_fields.get('payload_hex', cand.data_signature) if cand.j1939_fields else cand.data_signature
            print(f"    {cand.filename}: CAN={cand.can_id}, Line={cand.line_number}, Payload={payload_hex}")
    print(f"\n{'=' * 80}\nTOP RECOMMENDATION\n{'=' * 80}")
    if cross_log_matches:
        top = cross_log_matches[0]
        print(f"PGN: 0x{top.pgn:04X}, Source: 0x{top.source_address:02X}, Dest: 0x{top.destination_address:02X}, Similarity: {top.similarity_score:.2%}, Found in {len(top.candidates)} logs")


def find_multi_log_commands(config: Dict = None) -> Dict[str, Any]:
    """Main entry point for multi-log analysis."""
    if config is None:
        config = CONFIG
    paths = config.get('multi_log_paths')
    if not paths:
        print("Error: 'multi_log_paths' not configured in CONFIG")
        return {'error': 'No paths configured'}
    log_files = collect_log_files(paths)
    if not log_files:
        print(f"Error: No log files found in paths: {paths}")
        return {'error': 'No log files found'}
    print(f"Found {len(log_files)} log files:")
    for f in log_files:
        print(f"  - {os.path.basename(f)}")
    results = analyze_multi_log(log_files, config)
    print_multi_log_results(results, config)
    return results


def main():
    """Main entry point - dispatches between multi-log, offset-search, and absolute modes."""
    ts_fmt = CONFIG['timestamp_precision']

    if CONFIG.get('multi_log_paths'):
        find_multi_log_commands(CONFIG)
        return

    if CONFIG.get('relative_fire_times'):
        candidates = find_offset_command_from_config(CONFIG)
        print_offset_candidates(candidates, CONFIG)

        if not candidates:
            print(f"\nNo candidates found. Consider adjusting CONFIG parameters:")
            print(f"  - 'search_radius' (currently {CONFIG['search_radius']}s)")
            print(f"  - 'min_coverage' (currently {CONFIG['min_coverage']:.0%})")
            print(f"  - 'relative_fire_times' (currently {CONFIG['relative_fire_times']})")
            print(f"  - 'max_occurrences_per_slot' (currently {CONFIG['max_occurrences_per_slot']})")
        else:
            print(f"\nTop candidate: {candidates[0].can_id} with confidence {candidates[0].confidence:.3f}")
            print(f"Data pattern: [{candidates[0].data_signature}]")
            print(f"Best log offset (video t=0 aligns to log ts): {candidates[0].best_offset:.{ts_fmt}f}")
    else:
        candidates = find_command_from_config(CONFIG)
        print_command_candidates(candidates, CONFIG)

        if not candidates:
            print(f"\nNo candidates found. Consider adjusting CONFIG parameters:")
            print(f"  - 'search_radius' (currently {CONFIG['search_radius']}s)")
            print(f"  - 'min_coverage' (currently {CONFIG['min_coverage']:.0%})")
            print(f"  - 'command_fire_times' (currently {CONFIG['command_fire_times']})")
        else:
            print(f"\nTop candidate: {candidates[0].can_id} with confidence {candidates[0].confidence:.3f}")
            print(f"Data pattern: [{candidates[0].data_signature}]")


if __name__ == "__main__":
    main()
