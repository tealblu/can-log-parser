import re
from dataclasses import dataclass
from typing import List, Optional

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

class CANLogParser:
    """Parser for CAN log files in the specified format"""
    
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
    
    def filter_by_first_appearance_after(self, min_timestamp: float) -> List[CANMessage]:
        """
        Filter messages to only include CAN IDs that first appeared after the specified timestamp.
        This removes any CAN ID that had its first occurrence before min_timestamp.
        
        Args:
            min_timestamp: Only include CAN IDs that first appeared after this time
            
        Returns:
            List of CANMessage objects with filtered CAN IDs
        """
        if not self.messages:
            return []
        
        # Find the first occurrence timestamp for each CAN ID
        first_occurrence = {}
        for msg in self.messages:
            if msg.can_id not in first_occurrence:
                first_occurrence[msg.can_id] = msg.timestamp
        
        # Determine which CAN IDs first appeared after the threshold
        valid_can_ids = {
            can_id for can_id, first_time in first_occurrence.items() 
            if first_time >= min_timestamp
        }
        
        # Filter messages to only include valid CAN IDs
        filtered_messages = [
            msg for msg in self.messages 
            if msg.can_id in valid_can_ids
        ]
        
        print(f"Filtering by first appearance after {min_timestamp:.6f}s:")
        print(f"  Total CAN IDs: {len(first_occurrence)}")
        print(f"  CAN IDs appearing after threshold: {len(valid_can_ids)}")
        print(f"  Messages before filtering: {len(self.messages)}")
        print(f"  Messages after filtering: {len(filtered_messages)}")
        
        if valid_can_ids:
            print(f"  Valid CAN IDs: {sorted(valid_can_ids)}")
        
        return filtered_messages
    
    def dump_can_ids(self, sort_by: str = 'id') -> None:
        """
        Dump all CAN IDs found in the log with statistics
        
        Args:
            sort_by: How to sort the output - 'id', 'count', 'first_time', or 'last_time'
        """
        if not self.messages:
            print("No messages to analyze.")
            return
        
        # Collect statistics for each CAN ID
        can_id_stats = {}
        
        for msg in self.messages:
            if msg.can_id not in can_id_stats:
                can_id_stats[msg.can_id] = {
                    'count': 0,
                    'first_time': msg.timestamp,
                    'last_time': msg.timestamp,
                    'data_lengths': set()
                }
            
            stats = can_id_stats[msg.can_id]
            stats['count'] += 1
            stats['first_time'] = min(stats['first_time'], msg.timestamp)
            stats['last_time'] = max(stats['last_time'], msg.timestamp)
            stats['data_lengths'].add(msg.data_length)
        
        # Sort based on the specified criteria
        if sort_by == 'count':
            sorted_ids = sorted(can_id_stats.items(), key=lambda x: x[1]['count'], reverse=True)
        elif sort_by == 'first_time':
            sorted_ids = sorted(can_id_stats.items(), key=lambda x: x[1]['first_time'])
        elif sort_by == 'last_time':
            sorted_ids = sorted(can_id_stats.items(), key=lambda x: x[1]['last_time'])
        else:  # sort by 'id' (default)
            sorted_ids = sorted(can_id_stats.items())
        
        print(f"\n=== CAN ID Analysis (sorted by {sort_by}) ===")
        print(f"{'CAN ID':<12} {'Count':<8} {'First Time':<12} {'Last Time':<12} {'Duration':<10} {'Data Len'}")
        print("-" * 80)
        
        for can_id, stats in sorted_ids:
            duration = stats['last_time'] - stats['first_time']
            data_lens = ','.join(map(str, sorted(stats['data_lengths'])))
            
            print(f"{can_id:<12} {stats['count']:<8} "
                  f"{stats['first_time']:<12.6f} {stats['last_time']:<12.6f} "
                  f"{duration:<10.3f} {data_lens}")
        
        print(f"\nTotal unique CAN IDs: {len(can_id_stats)}")
        print(f"Total messages: {sum(stats['count'] for stats in can_id_stats.values())}")
    
    def get_can_ids_list(self) -> List[str]:
        """
        Return a simple list of all unique CAN IDs found in the log
        
        Returns:
            List of unique CAN ID strings
        """
        return list(set(msg.can_id for msg in self.messages))
    
    def print_can_id_data(self, target_can_id: str, max_messages: int = None, show_hex: bool = True) -> None:
        """
        Print all data for a specified CAN ID
        
        Args:
            target_can_id: The CAN ID to search for (case-sensitive)
            max_messages: Maximum number of messages to display (None = all)
            show_hex: Whether to show data in hex format (True) or decimal (False)
        """
        # Filter messages for the specified CAN ID
        matching_messages = [msg for msg in self.messages if msg.can_id == target_can_id]
        
        if not matching_messages:
            print(f"No messages found for CAN ID: {target_can_id}")
            available_ids = sorted(self.get_can_ids_list())
            print(f"Available CAN IDs: {available_ids[:10]}{'...' if len(available_ids) > 10 else ''}")
            return
        
        # Limit messages if specified
        if max_messages and len(matching_messages) > max_messages:
            print(f"Showing first {max_messages} of {len(matching_messages)} messages for CAN ID: {target_can_id}")
            display_messages = matching_messages[:max_messages]
        else:
            print(f"All {len(matching_messages)} messages for CAN ID: {target_can_id}")
            display_messages = matching_messages
        
        print(f"{'#':<6} {'Timestamp':<12} {'DL':<3} {'Data Bytes':<30} {'Line#':<6}")
        print("-" * 65)
        
        for i, msg in enumerate(display_messages, 1):
            if show_hex:
                data_str = ' '.join(f"{byte:>2}" for byte in msg.data_bytes)
            else:
                # Convert hex to decimal
                try:
                    data_str = ' '.join(f"{int(byte, 16):>3}" for byte in msg.data_bytes)
                except ValueError:
                    data_str = ' '.join(f"{byte:>3}" for byte in msg.data_bytes)  # Fallback if not hex
            
            print(f"{i:<6} {msg.timestamp:<12.6f} {msg.data_length:<3} {data_str:<30} {msg.line_number:<6}")
        
        # Show data analysis
        self._analyze_can_id_data(matching_messages, target_can_id)
    
    def _analyze_can_id_data(self, messages: List[CANMessage], can_id: str) -> None:
        """
        Analyze and display patterns in the data for a specific CAN ID
        
        Args:
            messages: List of messages for a specific CAN ID
            can_id: The CAN ID being analyzed
        """
        if not messages:
            return
        
        print(f"\n=== Data Analysis for {can_id} ===")
        
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
        
        # Data byte analysis
        data_lengths = set(msg.data_length for msg in messages)
        print(f"Data lengths used: {sorted(data_lengths)}")
        
        # Analyze each byte position for patterns
        if messages[0].data_length > 0:
            print("\nByte position analysis:")
            for byte_pos in range(max(msg.data_length for msg in messages)):
                byte_values = []
                for msg in messages:
                    if byte_pos < len(msg.data_bytes):
                        try:
                            byte_values.append(int(msg.data_bytes[byte_pos], 16))
                        except ValueError:
                            pass  # Skip non-hex values
                
                if byte_values:
                    unique_values = set(byte_values)
                    if len(unique_values) == 1:
                        print(f"  Byte {byte_pos}: Constant = 0x{byte_values[0]:02X} ({byte_values[0]})")
                    elif len(unique_values) <= 5:
                        hex_vals = [f"0x{v:02X}" for v in sorted(unique_values)]
                        print(f"  Byte {byte_pos}: {len(unique_values)} values = {', '.join(hex_vals)}")
                    else:
                        print(f"  Byte {byte_pos}: {len(unique_values)} different values, "
                              f"range: 0x{min(byte_values):02X}-0x{max(byte_values):02X} "
                              f"({min(byte_values)}-{max(byte_values)})")
    
    def get_messages_by_can_id(self, target_can_id: str) -> List[CANMessage]:
        """
        Get all messages for a specified CAN ID
        
        Args:
            target_can_id: The CAN ID to search for
            
        Returns:
            List of CANMessage objects matching the CAN ID
        """
        return [msg for msg in self.messages if msg.can_id == target_can_id]
    
    def print_summary(self) -> None:
        """Print a summary of the parsed data"""
        if not self.messages:
            print("No messages parsed yet.")
            return
            
        print(f"\n=== CAN Log Summary ===")
        print(f"Total messages: {len(self.messages)}")
        print(f"Time range: {self.messages[0].timestamp:.6f} - {self.messages[-1].timestamp:.6f}")
        
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
    parser = CANLogParser()
    
    # Parse a file (replace 'your_log_file.log' with actual filename)
    log_filename = "jaltest parameter and soot reset kvaser log 650k 2.txt"
    parser.parse_file("logs/" + log_filename)
    
    # Print summary
    parser.print_summary()
    
    # Example: Access the in-memory database
    messages = parser.get_messages()
    
    # You can now add filtering code here, for example:
    # - Filter by CAN ID: [msg for msg in messages if msg.can_id == '18EF8D1E']
    # - Filter by timestamp range: [msg for msg in messages if 0.01 <= msg.timestamp <= 0.02]
    # - Filter by data content: [msg for msg in messages if msg.data_bytes[0] == 'FF']
    
    print(f"\nReady for filtering! Database contains {len(messages)} messages.")

    filtered_messages = parser.filter_by_first_appearance_after(180.0)
    parser.messages = filtered_messages
    parser.print_summary()

    can_ids = parser.get_can_ids_list()
    print(f"Unique CAN IDs: {can_ids}")

    for can_id in can_ids:
        parser.print_can_id_data(can_id)