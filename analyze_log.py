import re
from dataclasses import dataclass
from typing import List, Optional, Tuple

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

class CANDataParser:
    """Parser for CAN log files focusing on unique data patterns"""
    
    def __init__(self):
        self.messages: List[CANMessage] = []
        
    def parse_line(self, line: str, line_num: int) -> Optional[CANMessage]:
        """
        Parse a single line from the CAN log
        Format: channel can_id format_flag data_length [variable data bytes] timestamp direction
        OR: channel can_id ErrorFrame timestamp direction (for error frames)
        """
        # Strip whitespace and skip empty lines
        line = line.strip()
        if not line:
            return None
            
        # Split the line into components
        parts = line.split()
        
        # Check for ErrorFrame format: channel can_id ErrorFrame timestamp direction
        if len(parts) >= 5 and "ErrorFrame" in parts:
            # Skip error frames - they don't contain CAN data
            return None
            
        # Validate minimum number of parts (channel + can_id + format + length + timestamp + direction = 6 minimum)
        if len(parts) < 6:
            print(f"Warning: Line {line_num} has insufficient parts: {line}")
            return None
            
        try:
            # Parse each component
            channel = int(parts[0])
            can_id = parts[1]
            format_flag = parts[2]
            data_length = int(parts[3])
            
            # Calculate where timestamp and direction should be based on data_length
            # Parts: [channel, can_id, format_flag, data_length, ...data_bytes..., timestamp, direction]
            expected_parts = 4 + data_length + 2  # 4 header parts + data bytes + timestamp + direction
            
            if len(parts) < expected_parts:
                print(f"Warning: Line {line_num} has insufficient parts for data length {data_length}: {line}")
                return None
            
            # Extract the actual number of data bytes specified by data_length
            data_bytes = parts[4:4+data_length]
            
            # Parse timestamp (after all data bytes)
            timestamp_index = 4 + data_length
            timestamp = float(parts[timestamp_index])
            
            # Direction flag (after timestamp)
            direction_index = timestamp_index + 1
            direction = parts[direction_index] if len(parts) > direction_index else ''
            
            # Validate we got the expected number of data bytes
            if len(data_bytes) != data_length:
                print(f"Warning: Line {line_num} data length mismatch - expected {data_length}, got {len(data_bytes)}: {line}")
                return None
                
            # Create and return CANMessage object
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
    
    def parse_file(self, filename: str) -> None:
        """Parse an entire CAN log file and build the in-memory database"""
        self.messages = []  # Reset the database
        error_frames = 0
        
        try:
            with open(filename, 'r') as file:
                for line_num, line in enumerate(file, 1):
                    # Check for error frames before parsing
                    if "ErrorFrame" in line:
                        error_frames += 1
                        continue
                        
                    message = self.parse_line(line, line_num)
                    if message:
                        self.messages.append(message)
                        
            print(f"Successfully parsed {len(self.messages)} CAN messages from {filename}")
            if error_frames > 0:
                print(f"Skipped {error_frames} error frames")
            
        except FileNotFoundError:
            print(f"Error: File '{filename}' not found")
        except Exception as e:
            print(f"Error reading file '{filename}': {e}")
    
    def get_message_count(self) -> int:
        """Return the total number of parsed messages"""
        return len(self.messages)
    
    def get_messages(self) -> List[CANMessage]:
        """Return all parsed messages"""
        return self.messages
    
    def filter_by_unique_data_after(self, min_timestamp: float) -> List[CANMessage]:
        """
        Filter messages to only include data patterns that first appeared after the specified timestamp.
        This removes any data pattern that had its first occurrence before min_timestamp.
        
        Args:
            min_timestamp: Only include data patterns that first appeared after this time
            
        Returns:
            List of CANMessage objects with filtered data patterns
        """
        if not self.messages:
            return []
        
        # Find the first occurrence timestamp for each unique data pattern
        first_occurrence = {}
        for msg in self.messages:
            data_pattern = msg.data_signature
            if data_pattern not in first_occurrence:
                first_occurrence[data_pattern] = msg.timestamp
        
        # Determine which data patterns first appeared after the threshold
        valid_data_patterns = {
            pattern for pattern, first_time in first_occurrence.items() 
            if first_time >= min_timestamp
        }
        
        # Filter messages to only include valid data patterns
        filtered_messages = [
            msg for msg in self.messages 
            if msg.data_signature in valid_data_patterns
        ]
        
        print(f"Filtering by unique data first appearance after {min_timestamp:.6f}s:")
        print(f"  Total unique data patterns: {len(first_occurrence)}")
        print(f"  Data patterns appearing after threshold: {len(valid_data_patterns)}")
        print(f"  Messages before filtering: {len(self.messages)}")
        print(f"  Messages after filtering: {len(filtered_messages)}")
        
        if valid_data_patterns:
            print(f"  Sample valid data patterns:")
            for i, pattern in enumerate(sorted(valid_data_patterns)[:5]):
                print(f"    {i+1}: [{pattern}]")
            if len(valid_data_patterns) > 5:
                print(f"    ... and {len(valid_data_patterns) - 5} more")
        
        return filtered_messages
    
    def dump_data_patterns(self, sort_by: str = 'first_time') -> None:
        """
        Dump all unique data patterns found in the log with statistics
        
        Args:
            sort_by: How to sort the output - 'pattern', 'count', 'first_time', or 'last_time'
        """
        if not self.messages:
            print("No messages to analyze.")
            return
        
        # Collect statistics for each data pattern
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
        
        # Sort based on the specified criteria
        if sort_by == 'count':
            sorted_patterns = sorted(pattern_stats.items(), key=lambda x: x[1]['count'], reverse=True)
        elif sort_by == 'pattern':
            sorted_patterns = sorted(pattern_stats.items())
        elif sort_by == 'last_time':
            sorted_patterns = sorted(pattern_stats.items(), key=lambda x: x[1]['last_time'])
        else:  # sort by 'first_time' (default)
            sorted_patterns = sorted(pattern_stats.items(), key=lambda x: x[1]['first_time'])
        
        print(f"\n=== Data Pattern Analysis (sorted by {sort_by}) ===")
        print(f"{'Data Pattern':<30} {'Count':<8} {'First Time':<12} {'Last Time':<12} {'Duration':<10} {'CAN IDs'}")
        print("-" * 100)
        
        for pattern, stats in sorted_patterns:
            duration = stats['last_time'] - stats['first_time']
            can_ids_str = ','.join(sorted(stats['can_ids']))[:20]  # Limit display length
            if len(can_ids_str) >= 20:
                can_ids_str += "..."
            
            # Truncate pattern if too long
            display_pattern = pattern[:28] + ".." if len(pattern) > 30 else pattern
            
            print(f"{display_pattern:<30} {stats['count']:<8} "
                  f"{stats['first_time']:<12.6f} {stats['last_time']:<12.6f} "
                  f"{duration:<10.3f} {can_ids_str}")
        
        print(f"\nTotal unique data patterns: {len(pattern_stats)}")
        print(f"Total messages: {sum(stats['count'] for stats in pattern_stats.values())}")
    
    def get_unique_data_patterns(self) -> List[str]:
        """
        Return a simple list of all unique data patterns found in the log
        
        Returns:
            List of unique data pattern strings
        """
        return list(set(msg.data_signature for msg in self.messages))
    
    def print_data_pattern_messages(self, target_pattern: str, max_messages: int = None, show_hex: bool = True) -> None:
        """
        Print all messages with a specified data pattern
        
        Args:
            target_pattern: The data pattern to search for (space-separated hex values)
            max_messages: Maximum number of messages to display (None = all)
            show_hex: Whether to show data in hex format (True) or decimal (False)
        """
        # Filter messages for the specified data pattern
        matching_messages = [msg for msg in self.messages if msg.data_signature == target_pattern]
        
        if not matching_messages:
            print(f"No messages found for data pattern: [{target_pattern}]")
            available_patterns = sorted(self.get_unique_data_patterns())
            print(f"Available patterns (first 5): {available_patterns[:5]}")
            return
        
        # Show pattern analysis
        self._analyze_data_pattern(matching_messages, target_pattern)
        
        # Limit messages if specified
        if max_messages and len(matching_messages) > max_messages:
            print(f"Showing first {max_messages} of {len(matching_messages)} messages for pattern: [{target_pattern}]")
            display_messages = matching_messages[:max_messages]
        else:
            print(f"All {len(matching_messages)} messages for pattern: [{target_pattern}]")
            display_messages = matching_messages
        
        print(f"{'#':<6} {'CAN ID':<12} {'Timestamp':<12} {'DL':<3} {'Data Bytes':<30} {'Line#':<6}")
        print("-" * 75)
        
        for i, msg in enumerate(display_messages, 1):
            if show_hex:
                data_str = ' '.join(f"{byte:>2}" for byte in msg.data_bytes)
            else:
                # Convert hex to decimal
                try:
                    data_str = ' '.join(f"{int(byte, 16):>3}" for byte in msg.data_bytes)
                except ValueError:
                    data_str = ' '.join(f"{byte:>3}" for byte in msg.data_bytes)  # Fallback if not hex
            
            print(f"{i:<6} {msg.can_id:<12} {msg.timestamp:<12.6f} {msg.data_length:<3} {data_str:<30} {msg.line_number:<6}")
    
    def _analyze_data_pattern(self, messages: List[CANMessage], pattern: str) -> None:
        """
        Analyze and display information about messages with a specific data pattern
        
        Args:
            messages: List of messages with the same data pattern
            pattern: The data pattern being analyzed
        """
        if not messages:
            return
        
        print(f"\n=== Pattern Analysis for [{pattern}] ===")
        
        # Time analysis
        first_msg = messages[0]
        last_msg = messages[-1]
        total_duration = last_msg.timestamp - first_msg.timestamp
        
        if len(messages) > 1:
            intervals = []
            for i in range(1, len(messages)):
                interval = messages[i].timestamp - messages[i-1].timestamp
                intervals.append(interval)
            
            avg_interval = sum(intervals) / len(intervals)
            min_interval = min(intervals)
            max_interval = max(intervals)
            
            print(f"Timing: {total_duration:.3f}s total, avg interval: {avg_interval:.6f}s, "
                  f"range: {min_interval:.6f}s - {max_interval:.6f}s")
        
        # CAN ID analysis
        can_ids = set(msg.can_id for msg in messages)
        print(f"Used by {len(can_ids)} different CAN ID(s): {sorted(can_ids)}")
        
        # Channel analysis
        channels = set(msg.channel for msg in messages)
        print(f"Seen on channel(s): {sorted(channels)}")
    
    def get_messages_by_data_pattern(self, target_pattern: str) -> List[CANMessage]:
        """
        Get all messages with a specified data pattern
        
        Args:
            target_pattern: The data pattern to search for
            
        Returns:
            List of CANMessage objects matching the data pattern
        """
        return [msg for msg in self.messages if msg.data_signature == target_pattern]
    
    def find_similar_patterns(self, reference_pattern: str, max_differences: int = 1) -> List[Tuple[str, int]]:
        """
        Find data patterns similar to a reference pattern
        
        Args:
            reference_pattern: The pattern to compare against
            max_differences: Maximum number of differing bytes to consider similar
            
        Returns:
            List of tuples (pattern, difference_count) sorted by similarity
        """
        ref_bytes = reference_pattern.split()
        similar_patterns = []
        
        for msg in self.messages:
            msg_bytes = msg.data_bytes
            
            # Only compare patterns of the same length
            if len(msg_bytes) != len(ref_bytes):
                continue
                
            # Count differences
            differences = sum(1 for a, b in zip(ref_bytes, msg_bytes) if a != b)
            
            if 0 < differences <= max_differences:
                pattern = msg.data_signature
                if pattern not in [p[0] for p in similar_patterns]:
                    similar_patterns.append((pattern, differences))
        
        # Sort by number of differences
        similar_patterns.sort(key=lambda x: x[1])
        return similar_patterns
    
    def print_summary(self) -> None:
        """Print a summary of the parsed data"""
        if not self.messages:
            print("No messages parsed yet.")
            return
            
        print(f"\n=== CAN Log Summary ===")
        print(f"Total messages: {len(self.messages)}")
        print(f"Time range: {self.messages[0].timestamp:.6f} - {self.messages[-1].timestamp:.6f}")
        
        # Count unique data patterns
        unique_patterns = set(msg.data_signature for msg in self.messages)
        print(f"Unique data patterns: {len(unique_patterns)}")
        
        # Count unique CAN IDs
        unique_ids = set(msg.can_id for msg in self.messages)
        print(f"Unique CAN IDs: {len(unique_ids)}")
        
        # Count by channel
        channels = {}
        for msg in self.messages:
            channels[msg.channel] = channels.get(msg.channel, 0) + 1
        print(f"Messages by channel: {dict(sorted(channels.items()))}")
        
        # Count by data length
        data_lengths = {}
        for msg in self.messages:
            data_lengths[msg.data_length] = data_lengths.get(msg.data_length, 0) + 1
        print(f"Messages by data length: {dict(sorted(data_lengths.items()))}")
        
        print(f"\nFirst few messages:")
        for i, msg in enumerate(self.messages[:5]):
            data_str = ' '.join(msg.data_bytes)
            print(f"  {i+1}: CH{msg.channel} {msg.can_id} DL:{msg.data_length} [{data_str}] @ {msg.timestamp:.6f}")

if __name__ == "__main__":
    # Create parser instance
    parser = CANDataParser()
    
    # Parse a file (replace 'your_log_file.log' with actual filename)
    log_filename = "jaltest parameter and soot reset kvaser log 650k 2.txt"
    parser.parse_file("logs/" + log_filename)
    
    # Print summary
    parser.print_summary()
    
    # Example: Access the in-memory database
    messages = parser.get_messages()
    
    # Filter by unique data patterns appearing after timestamp
    filtered_messages = parser.filter_by_unique_data_after(180.0)
    
    # Show data pattern statistics
    parser.dump_data_patterns(sort_by='first_time')
    
    print(f"\nReady for data pattern analysis! Database contains {len(messages)} messages.")
    print(f"Found {len(filtered_messages)} messages with data patterns first appearing after 180.0s")