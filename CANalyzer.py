import re
from dataclasses import dataclass
from typing import List, Optional, Tuple, Dict, Set, Any

@dataclass
class CANMessage:
    """Represents a single CAN message from the log"""
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
        """Return a string representation of the data bytes for comparison"""
        return ' '.join(self.data_bytes)

class CANDataPatternAnalyzer:
    """Core analyzer for CAN data patterns"""
    
    def __init__(self, messages: List[CANMessage]):
        self.messages = messages
    
    def filter_by_unique_data_after(self, min_timestamp: float) -> List[CANMessage]:
        """Filter messages to only include data patterns first appearing after min_timestamp"""
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
    
    def _get_first_occurrence_times(self) -> Dict[str, float]:
        """Get first occurrence timestamp for each data pattern"""
        first_occurrence = {}
        for msg in self.messages:
            pattern = msg.data_signature
            if pattern not in first_occurrence:
                first_occurrence[pattern] = msg.timestamp
        return first_occurrence
    
    def _print_filter_stats(self, min_timestamp: float, 
                          first_occurrence: Dict[str, float],
                          valid_patterns: Set[str]) -> None:
        """Print statistics about the filtering operation"""
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
        """Dump all unique data patterns with statistics"""
        if not self.messages:
            print("No messages to analyze.")
            return
        
        pattern_stats = self._collect_pattern_statistics()
        sorted_patterns = self._sort_patterns(pattern_stats, sort_by)
        self._print_pattern_analysis(sorted_patterns, sort_by)
    
    def _collect_pattern_statistics(self) -> Dict[str, Dict[str, Any]]:
        """Collect statistics for each data pattern"""
        pattern_stats = {}
        for msg in self.messages:
            pattern = msg.data_signature
            if pattern not in pattern_stats:
                pattern_stats[pattern] = {
                    'count': 0,
                    'first_time': msg.timestamp,
                    'last_time': msg.timestamp,
                    'can_ids': set(),
                    'first_msg': msg
                }
            
            stats = pattern_stats[pattern]
            stats['count'] += 1
            stats['first_time'] = min(stats['first_time'], msg.timestamp)
            stats['last_time'] = max(stats['last_time'], msg.timestamp)
            stats['can_ids'].add(msg.can_id)
        return pattern_stats
    
    def _sort_patterns(self, pattern_stats: Dict[str, Dict[str, Any]], 
                      sort_by: str) -> List[Tuple[str, Dict[str, Any]]]:
        """Sort patterns based on specified criteria"""
        if sort_by == 'count':
            return sorted(pattern_stats.items(), key=lambda x: x[1]['count'], reverse=True)
        elif sort_by == 'pattern':
            return sorted(pattern_stats.items())
        elif sort_by == 'last_time':
            return sorted(pattern_stats.items(), key=lambda x: x[1]['last_time'])
        else:  # 'first_time' (default)
            return sorted(pattern_stats.items(), key=lambda x: x[1]['first_time'])
    
    def _print_pattern_analysis(self, sorted_patterns: List[Tuple[str, Dict[str, Any]]], 
                              sort_by: str) -> None:
        """Print the pattern analysis results"""
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
        """Return a list of all unique data patterns"""
        return list(set(msg.data_signature for msg in self.messages))
    
    def print_data_pattern_messages(self, target_pattern: str, 
                                  max_messages: int = None, 
                                  show_hex: bool = True) -> None:
        """Print all messages with a specified data pattern"""
        matching_messages = self.get_messages_by_data_pattern(target_pattern)
        
        if not matching_messages:
            self._print_no_matching_patterns(target_pattern)
            return
        
        self._analyze_data_pattern(matching_messages, target_pattern)
        self._print_matching_messages(matching_messages, target_pattern, max_messages, show_hex)
    
    def _print_no_matching_patterns(self, target_pattern: str) -> None:
        """Handle case when no messages match the target pattern"""
        print(f"No messages found for data pattern: [{target_pattern}]")
        available_patterns = sorted(self.get_unique_data_patterns())
        print(f"Available patterns (first 5): {available_patterns[:5]}")
    
    def _print_matching_messages(self, messages: List[CANMessage], 
                               target_pattern: str,
                               max_messages: int,
                               show_hex: bool) -> None:
        """Print the matching messages in a formatted table"""
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
        """Format data bytes as either hex or decimal"""
        if show_hex:
            return ' '.join(f"{byte:>2}" for byte in data_bytes)
        try:
            return ' '.join(f"{int(byte, 16):>3}" for byte in data_bytes)
        except ValueError:
            return ' '.join(f"{byte:>3}" for byte in data_bytes)

    def _analyze_data_pattern(self, messages: List[CANMessage], pattern: str) -> None:
        """Analyze and display information about a specific data pattern"""
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
        """Calculate time intervals between consecutive messages"""
        intervals = []
        for i in range(1, len(messages)):
            intervals.append(messages[i].timestamp - messages[i-1].timestamp)
        return intervals

    def get_messages_by_data_pattern(self, target_pattern: str) -> List[CANMessage]:
        """Get all messages with a specified data pattern"""
        return [msg for msg in self.messages if msg.data_signature == target_pattern]
    
    def find_similar_patterns(self, reference_pattern: str, 
                            max_differences: int = 1) -> List[Tuple[str, int]]:
        """Find data patterns similar to a reference pattern"""
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

class CANLogParser:
    """Parser for Kvaser CAN log files"""
    
    def __init__(self):
        self.messages: List[CANMessage] = []
    
    def parse_file(self, filename: str) -> None:
        """Parse an entire CAN log file"""
        self.messages = []
        error_frames = 0
        
        try:
            with open(filename, 'r') as file:
                for line_num, line in enumerate(file, 1):
                    if "ErrorFrame" in line:
                        error_frames += 1
                        continue
                        
                    message = self._parse_line(line, line_num)
                    if message:
                        self.messages.append(message)
            
            print(f"Successfully parsed {len(self.messages)} CAN messages from {filename}")
            if error_frames > 0:
                print(f"Skipped {error_frames} error frames")
            
        except FileNotFoundError:
            print(f"Error: File '{filename}' not found")
        except Exception as e:
            print(f"Error reading file '{filename}': {e}")
    
    def _parse_line(self, line: str, line_num: int) -> Optional[CANMessage]:
        """Parse a single line from the CAN log"""
        line = line.strip()
        if not line:
            return None
            
        parts = line.split()
        if len(parts) < 6:
            print(f"Warning: Line {line_num} has insufficient parts: {line}")
            return None
            
        try:
            channel = int(parts[0])
            can_id = parts[1]
            format_flag = parts[2]
            data_length = int(parts[3])
            
            expected_parts = 4 + data_length + 2
            if len(parts) < expected_parts:
                print(f"Warning: Line {line_num} has insufficient parts for data length {data_length}: {line}")
                return None
            
            data_bytes = parts[4:4+data_length]
            timestamp = float(parts[4+data_length])
            direction = parts[4+data_length+1] if len(parts) > 4+data_length+1 else ''
            
            if len(data_bytes) != data_length:
                print(f"Warning: Line {line_num} data length mismatch - expected {data_length}, got {len(data_bytes)}: {line}")
                return None
                
            return CANMessage(
                channel=channel,
                can_id=can_id,
                format_flag=format_flag,
                data_length=data_length,
                data_bytes=data_bytes,
                timestamp=timestamp,
                direction=direction,
                raw_line=line,
                line_number=line_num
            )
            
        except (ValueError, IndexError) as e:
            print(f"Error parsing line {line_num}: {e}")
            print(f"Line content: {line}")
            return None
    
    def get_messages(self) -> List[CANMessage]:
        """Return all parsed messages"""
        return self.messages
    
    def get_message_count(self) -> int:
        """Return the total number of parsed messages"""
        return len(self.messages)
    
    def create_analyzer(self) -> CANDataPatternAnalyzer:
        """Create a data pattern analyzer for the parsed messages"""
        return CANDataPatternAnalyzer(self.messages)
    
    def print_summary(self) -> None:
        """Print a summary of the parsed data"""
        if not self.messages:
            print("No messages parsed yet.")
            return
            
        print(f"\n=== CAN Log Summary ===")
        print(f"Total messages: {len(self.messages)}")
        print(f"Time range: {self.messages[0].timestamp:.6f} - {self.messages[-1].timestamp:.6f}")
        
        unique_patterns = set(msg.data_signature for msg in self.messages)
        print(f"Unique data patterns: {len(unique_patterns)}")
        
        unique_ids = set(msg.can_id for msg in self.messages)
        print(f"Unique CAN IDs: {len(unique_ids)}")
        
        channels = {}
        for msg in self.messages:
            channels[msg.channel] = channels.get(msg.channel, 0) + 1
        print(f"Messages by channel: {dict(sorted(channels.items()))}")
        
        data_lengths = {}
        for msg in self.messages:
            data_lengths[msg.data_length] = data_lengths.get(msg.data_length, 0) + 1
        print(f"Messages by data length: {dict(sorted(data_lengths.items()))}")
        
        print(f"\nFirst few messages:")
        for i, msg in enumerate(self.messages[:5]):
            data_str = ' '.join(msg.data_bytes)
            print(f"  {i+1}: CH{msg.channel} {msg.can_id} DL:{msg.data_length} [{data_str}] @ {msg.timestamp:.6f}")

def main():
    """Example usage of the CAN log analysis tool"""
    # Create parser instance
    parser = CANLogParser()
    
    # Parse a file
    log_filename = "jaltest parameter and soot reset kvaser log 650k 2.txt"
    parser.parse_file("logs/" + log_filename)
    
    # Print summary
    parser.print_summary()
    
    # Create analyzer for pattern analysis
    analyzer = parser.create_analyzer()
    
    # Filter by unique data patterns appearing after timestamp
    filtered_messages = analyzer.filter_by_unique_data_after(180.0)
    
    # Show data pattern statistics
    analyzer.dump_data_patterns(sort_by='first_time')
    
    print(f"\nReady for data pattern analysis! Database contains {parser.get_message_count()} messages.")
    print(f"Found {len(filtered_messages)} messages with data patterns first appearing after 180.0s")

if __name__ == "__main__":
    main()