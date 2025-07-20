# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a C++ PCAP (packet capture) file analyzer tool that processes network capture files to extract timing information, perform traffic analysis, and provide detailed statistics about network connections.

## Build Commands

```bash
# Build the project
make

# Clean build artifacts
make clean

# Install to /usr/local/bin (requires sudo)
sudo make install

# Format code before committing (per user instructions)
clang-format --style=WebKit -i pcap_analyzer.cpp
```

## Development Dependencies

- **libpcap**: Required for PCAP file parsing (`-lpcap`)
- **C++17**: Project uses modern C++ features (filesystem API)
- **Compiler**: g++ with optimization level O2

## Usage

```bash
# Basic usage - analyze PCAP files in a directory
./pcap_analyzer /path/to/pcaps

# With IP address and port analysis
./pcap_analyzer /path/to/pcaps -ips

# Output in JSON format with IP analysis
./pcap_analyzer /path/to/pcaps -json -ips

# Output in XML format
./pcap_analyzer /path/to/pcaps -xml
```

## Architecture

The project consists of a single C++ file (`pcap_analyzer.cpp`) that implements:

1. **PCAP File Processing**: Scans directories for PCAP files (.pcap, .cap, .pcapng, .dmp)
2. **Packet Analysis**: Extracts timing, protocol, and connection information
3. **Network Statistics**: 
   - Protocol distribution (IPv4, IPv6, TCP, UDP)
   - Top source/destination IPs and ports
   - Connection tracking and statistics
4. **Output Formats**: Supports text, XML, and JSON output
5. **Gap Analysis**: Identifies time gaps between sequential capture files

## Key Data Structures

- `PcapFileInfo`: Stores metadata about each PCAP file
- `NetworkStats`: Aggregates network traffic statistics
- `ConnectionInfo`: Tracks individual network connections
- `GapInfo`: Records timing gaps between files

## Output Format Options

- **Text** (default): Human-readable tabular format
- **XML** (`-xml`): Structured XML output
- **JSON** (`-json`): Machine-readable JSON format

## Important Notes

- The analyzer uses libpcap for packet parsing
- Supports both IPv4 and IPv6 packet analysis
- Connection tracking is based on 5-tuple (src_ip, dst_ip, src_port, dst_port, protocol)
- Time analysis assumes PCAP files contain accurate timestamps