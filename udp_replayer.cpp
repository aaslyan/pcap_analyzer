#include <algorithm>
#include <arpa/inet.h>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <getopt.h>
#include <iostream>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <optional>
#include <pcap.h>
#include <regex>
#include <set>
#include <sstream>
#include <string>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>

namespace fs = std::filesystem;

enum SourceMode {
    PRESERVE_ORIGINAL, // Keep original src IP:port (requires raw sockets)
    USE_INTERFACE, // Use outgoing interface IP
    SPOOF_CUSTOM // Use specified source
};

enum ProtocolType {
    PROTO_ANY,
    PROTO_DNS,
    PROTO_DHCP,
    PROTO_NTP,
    PROTO_SYSLOG,
    PROTO_SNMP
};

enum ReplaySpeed {
    ORIGINAL_SPEED, // Preserve inter-packet delays
    CONSTANT_RATE, // Fixed packets/second
    MAX_SPEED // As fast as possible
};

struct PortRange {
    uint16_t min_port;
    uint16_t max_port;

    bool contains(uint16_t port) const
    {
        return port >= min_port && port <= max_port;
    }
};

struct ReplayFilter {
    std::optional<std::string> src_ip;
    std::optional<uint16_t> src_port; // 0 = any
    std::set<uint16_t> src_ports; // Multiple specific ports
    std::vector<PortRange> src_port_ranges; // Port ranges

    std::optional<std::string> dst_ip;
    std::optional<uint16_t> dst_port; // 0 = any
    std::set<uint16_t> dst_ports; // Multiple specific ports
    std::vector<PortRange> dst_port_ranges; // Port ranges

    ProtocolType protocol = PROTO_ANY;
};

struct Target {
    std::string ip;
    uint16_t port;
};

struct CustomSource {
    std::string ip;
    uint16_t port;
};

struct ReplayConfig {
    std::string pcap_file;
    std::vector<ReplayFilter> filters;
    std::vector<Target> targets;
    SourceMode source_mode = USE_INTERFACE;
    std::optional<CustomSource> custom_source;
    ReplaySpeed replay_speed = ORIGINAL_SPEED;
    double rate_multiplier = 1.0; // For CONSTANT_RATE mode
    int packet_count = -1; // -1 = all packets
    bool verbose = false;
    std::string interface_name = "eth0"; // For raw sockets
};

struct PacketInfo {
    std::string src_ip;
    uint16_t src_port;
    std::string dst_ip;
    uint16_t dst_port;
    std::vector<uint8_t> payload;
    struct timeval timestamp;
};

// Protocol detection based on port and payload
ProtocolType detectProtocol(uint16_t port, const std::vector<uint8_t>& payload)
{
    // Check well-known ports first
    switch (port) {
    case 53:
        return PROTO_DNS;
    case 67:
    case 68:
        return PROTO_DHCP;
    case 123:
        return PROTO_NTP;
    case 514:
        return PROTO_SYSLOG;
    case 161:
    case 162:
        return PROTO_SNMP;
    default:
        break;
    }

    // Check payload patterns for protocol detection
    if (payload.size() >= 12) {
        // DNS: Check for DNS header pattern
        if (port == 53 || (payload.size() >= 12 && (payload[2] & 0x80) == 0x00 && // QR bit = 0 (query)
                (payload[2] & 0x78) == 0x00)) { // Opcode = 0 (standard query)
            return PROTO_DNS;
        }
    }

    if (payload.size() >= 4) {
        // DHCP: Check for DHCP magic cookie
        if (payload.size() >= 240 && payload[0] == 0x01 && // BOOTREQUEST
            payload[236] == 0x63 && payload[237] == 0x82 && payload[238] == 0x53 && payload[239] == 0x63) {
            return PROTO_DHCP;
        }

        // NTP: Check for NTP header
        if (payload.size() == 48 && (payload[0] & 0x38) == 0x18) { // Version 3
            return PROTO_NTP;
        }
    }

    return PROTO_ANY;
}

// Parse port specification (single, comma-separated, or ranges)
bool parsePortSpec(const std::string& port_spec, std::set<uint16_t>& ports, std::vector<PortRange>& ranges)
{
    std::stringstream ss(port_spec);
    std::string item;

    while (std::getline(ss, item, ',')) {
        // Remove whitespace
        item.erase(0, item.find_first_not_of(" \t"));
        item.erase(item.find_last_not_of(" \t") + 1);

        // Check if it's a range (contains '-')
        size_t dash_pos = item.find('-');
        if (dash_pos != std::string::npos) {
            try {
                uint16_t min_port = std::stoi(item.substr(0, dash_pos));
                uint16_t max_port = std::stoi(item.substr(dash_pos + 1));
                if (min_port <= max_port) {
                    ranges.push_back({ min_port, max_port });
                } else {
                    return false;
                }
            } catch (...) {
                return false;
            }
        } else {
            // Single port
            try {
                uint16_t port = std::stoi(item);
                ports.insert(port);
            } catch (...) {
                return false;
            }
        }
    }

    return true;
}

// Parse protocol string
ProtocolType parseProtocol(const std::string& proto_str)
{
    std::string proto_lower = proto_str;
    std::transform(proto_lower.begin(), proto_lower.end(), proto_lower.begin(), ::tolower);

    if (proto_lower == "dns")
        return PROTO_DNS;
    if (proto_lower == "dhcp")
        return PROTO_DHCP;
    if (proto_lower == "ntp")
        return PROTO_NTP;
    if (proto_lower == "syslog")
        return PROTO_SYSLOG;
    if (proto_lower == "snmp")
        return PROTO_SNMP;

    return PROTO_ANY;
}

// Parse IP:port string
bool parseTarget(const std::string& target_str, Target& target)
{
    size_t colon_pos = target_str.rfind(':');
    if (colon_pos == std::string::npos) {
        return false;
    }

    target.ip = target_str.substr(0, colon_pos);
    try {
        target.port = std::stoi(target_str.substr(colon_pos + 1));
    } catch (...) {
        return false;
    }

    return true;
}

// Parse custom source string
bool parseCustomSource(const std::string& source_str, CustomSource& source)
{
    size_t colon_pos = source_str.rfind(':');
    if (colon_pos == std::string::npos) {
        return false;
    }

    source.ip = source_str.substr(0, colon_pos);
    try {
        source.port = std::stoi(source_str.substr(colon_pos + 1));
    } catch (...) {
        return false;
    }

    return true;
}

// Parse filter string like "192.168.1.50:*->*:53"
bool parseFilter(const std::string& filter_str, ReplayFilter& filter)
{
    // Simple parsing for now - can be enhanced
    // Format: [src_ip]:[src_port]->[dst_ip]:[dst_port]
    // Use * for any

    size_t arrow_pos = filter_str.find("->");
    if (arrow_pos == std::string::npos) {
        return false;
    }

    std::string src_part = filter_str.substr(0, arrow_pos);
    std::string dst_part = filter_str.substr(arrow_pos + 2);

    // Parse source
    size_t src_colon = src_part.find(':');
    if (src_colon != std::string::npos) {
        std::string src_ip_str = src_part.substr(0, src_colon);
        std::string src_port_str = src_part.substr(src_colon + 1);

        if (src_ip_str != "*") {
            filter.src_ip = src_ip_str;
        }
        if (src_port_str != "*") {
            try {
                filter.src_port = std::stoi(src_port_str);
            } catch (...) {
                return false;
            }
        }
    }

    // Parse destination
    size_t dst_colon = dst_part.find(':');
    if (dst_colon != std::string::npos) {
        std::string dst_ip_str = dst_part.substr(0, dst_colon);
        std::string dst_port_str = dst_part.substr(dst_colon + 1);

        if (dst_ip_str != "*") {
            filter.dst_ip = dst_ip_str;
        }
        if (dst_port_str != "*") {
            try {
                filter.dst_port = std::stoi(dst_port_str);
            } catch (...) {
                return false;
            }
        }
    }

    return true;
}

// Check if port matches port specification
bool matchesPortSpec(uint16_t port, const std::optional<uint16_t>& single_port,
    const std::set<uint16_t>& ports, const std::vector<PortRange>& ranges)
{
    // Check single port
    if (single_port && port != *single_port) {
        return false;
    }

    // Check multiple ports
    if (!ports.empty() && ports.find(port) == ports.end()) {
        // Not in the port set, check ranges
        bool in_range = false;
        for (const auto& range : ranges) {
            if (range.contains(port)) {
                in_range = true;
                break;
            }
        }
        if (!in_range && ranges.empty()) {
            return false; // Not in ports and no ranges
        }
        if (!in_range && !ranges.empty()) {
            return false; // Not in any range
        }
    }

    // Check ranges if no specific ports
    if (ports.empty() && !ranges.empty()) {
        bool in_range = false;
        for (const auto& range : ranges) {
            if (range.contains(port)) {
                in_range = true;
                break;
            }
        }
        if (!in_range) {
            return false;
        }
    }

    return true;
}

// Check if packet matches filter
bool matchesFilter(const PacketInfo& packet, const ReplayFilter& filter)
{
    // Check source IP
    if (filter.src_ip && packet.src_ip != *filter.src_ip) {
        return false;
    }

    // Check destination IP
    if (filter.dst_ip && packet.dst_ip != *filter.dst_ip) {
        return false;
    }

    // Check source port
    if (filter.src_port || !filter.src_ports.empty() || !filter.src_port_ranges.empty()) {
        if (!matchesPortSpec(packet.src_port, filter.src_port, filter.src_ports, filter.src_port_ranges)) {
            return false;
        }
    }

    // Check destination port
    if (filter.dst_port || !filter.dst_ports.empty() || !filter.dst_port_ranges.empty()) {
        if (!matchesPortSpec(packet.dst_port, filter.dst_port, filter.dst_ports, filter.dst_port_ranges)) {
            return false;
        }
    }

    // Check protocol
    if (filter.protocol != PROTO_ANY) {
        ProtocolType detected = detectProtocol(packet.dst_port, packet.payload);
        if (detected != filter.protocol) {
            return false;
        }
    }

    return true;
}

// Check if packet matches any filter
bool matchesAnyFilter(const PacketInfo& packet, const std::vector<ReplayFilter>& filters)
{
    if (filters.empty()) {
        return true; // No filters = match all
    }

    for (const auto& filter : filters) {
        if (matchesFilter(packet, filter)) {
            return true;
        }
    }
    return false;
}

// Extract UDP packet information
bool extractUDPPacket(const u_char* packet_data, struct pcap_pkthdr* header, PacketInfo& info)
{
    // Ethernet header is typically 14 bytes
    const int ethernet_header_len = 14;

    if (header->caplen < ethernet_header_len) {
        return false;
    }

    // Get Ethernet type
    uint16_t ether_type = ntohs(*((uint16_t*)(packet_data + 12)));

    // Only process IPv4 for now
    if (ether_type != 0x0800) {
        return false;
    }

    const struct ip* ip_header = (struct ip*)(packet_data + ethernet_header_len);

    if (header->caplen < ethernet_header_len + sizeof(struct ip)) {
        return false;
    }

    // Only process UDP
    if (ip_header->ip_p != IPPROTO_UDP) {
        return false;
    }

    int ip_header_len = ip_header->ip_hl * 4;

    if (header->caplen < ethernet_header_len + ip_header_len + sizeof(struct udphdr)) {
        return false;
    }

    const struct udphdr* udp_header = (struct udphdr*)(packet_data + ethernet_header_len + ip_header_len);

    // Extract information
    char src_addr[INET_ADDRSTRLEN];
    char dst_addr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->ip_src), src_addr, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dst_addr, INET_ADDRSTRLEN);

    info.src_ip = src_addr;
    info.dst_ip = dst_addr;
    info.src_port = ntohs(udp_header->source);
    info.dst_port = ntohs(udp_header->dest);
    info.timestamp = header->ts;

    // Extract UDP payload
    int udp_header_len = sizeof(struct udphdr);
    int payload_offset = ethernet_header_len + ip_header_len + udp_header_len;
    int payload_len = ntohs(udp_header->len) - udp_header_len;

    if (payload_len > 0 && header->caplen >= payload_offset + payload_len) {
        info.payload.resize(payload_len);
        memcpy(info.payload.data(), packet_data + payload_offset, payload_len);
    }

    return true;
}

// Calculate checksum
uint16_t checksum(const void* data, size_t len)
{
    const uint16_t* buf = static_cast<const uint16_t*>(data);
    uint32_t sum = 0;

    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }

    if (len == 1) {
        sum += *(uint8_t*)buf << 8;
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return ~sum;
}

// Calculate UDP checksum
uint16_t udp_checksum(const struct ip* ip_hdr, const struct udphdr* udp_hdr, const void* data, size_t data_len)
{
    struct {
        uint32_t src_addr;
        uint32_t dest_addr;
        uint8_t zero;
        uint8_t protocol;
        uint16_t udp_len;
    } pseudo_hdr;

    pseudo_hdr.src_addr = ip_hdr->ip_src.s_addr;
    pseudo_hdr.dest_addr = ip_hdr->ip_dst.s_addr;
    pseudo_hdr.zero = 0;
    pseudo_hdr.protocol = IPPROTO_UDP;
    pseudo_hdr.udp_len = udp_hdr->len;

    uint32_t sum = 0;

    // Pseudo header
    const uint16_t* pseudo = reinterpret_cast<const uint16_t*>(&pseudo_hdr);
    for (size_t i = 0; i < sizeof(pseudo_hdr) / 2; i++) {
        sum += ntohs(pseudo[i]);
    }

    // UDP header
    const uint16_t* udp = reinterpret_cast<const uint16_t*>(udp_hdr);
    for (size_t i = 0; i < sizeof(struct udphdr) / 2; i++) {
        if (i == 3)
            continue; // Skip checksum field
        sum += ntohs(udp[i]);
    }

    // Data
    const uint16_t* data_ptr = static_cast<const uint16_t*>(data);
    size_t remaining = data_len;
    while (remaining > 1) {
        sum += ntohs(*data_ptr++);
        remaining -= 2;
    }

    if (remaining == 1) {
        sum += ntohs(*(uint8_t*)data_ptr << 8);
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return ~sum;
}

// Send UDP packet using raw sockets (for IP spoofing)
bool sendUDPPacketRaw(const PacketInfo& packet, const Target& target, const ReplayConfig& config)
{
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sock < 0) {
        std::cerr << "Failed to create raw socket: " << strerror(errno) << std::endl;
        std::cerr << "Note: Raw sockets require root privileges" << std::endl;
        return false;
    }

    int one = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        std::cerr << "Failed to set IP_HDRINCL: " << strerror(errno) << std::endl;
        close(sock);
        return false;
    }

    // Prepare packet buffer
    size_t packet_size = sizeof(struct ip) + sizeof(struct udphdr) + packet.payload.size();
    std::vector<uint8_t> packet_buffer(packet_size);

    // IP header
    struct ip* ip_hdr = reinterpret_cast<struct ip*>(packet_buffer.data());
    memset(ip_hdr, 0, sizeof(struct ip));
    ip_hdr->ip_hl = 5;
    ip_hdr->ip_v = 4;
    ip_hdr->ip_tos = 0;
    ip_hdr->ip_len = htons(packet_size);
    ip_hdr->ip_id = htons(getpid());
    ip_hdr->ip_off = 0;
    ip_hdr->ip_ttl = 64;
    ip_hdr->ip_p = IPPROTO_UDP;
    ip_hdr->ip_sum = 0;

    // Set source IP based on mode
    if (config.source_mode == PRESERVE_ORIGINAL) {
        inet_pton(AF_INET, packet.src_ip.c_str(), &ip_hdr->ip_src);
    } else if (config.source_mode == SPOOF_CUSTOM && config.custom_source) {
        inet_pton(AF_INET, config.custom_source->ip.c_str(), &ip_hdr->ip_src);
    } else {
        // Use interface IP (will be filled by kernel)
        ip_hdr->ip_src.s_addr = INADDR_ANY;
    }

    inet_pton(AF_INET, target.ip.c_str(), &ip_hdr->ip_dst);

    // Calculate IP checksum
    ip_hdr->ip_sum = checksum(ip_hdr, sizeof(struct ip));

    // UDP header
    struct udphdr* udp_hdr = reinterpret_cast<struct udphdr*>(packet_buffer.data() + sizeof(struct ip));
    memset(udp_hdr, 0, sizeof(struct udphdr));

    if (config.source_mode == PRESERVE_ORIGINAL) {
        udp_hdr->source = htons(packet.src_port);
    } else if (config.source_mode == SPOOF_CUSTOM && config.custom_source) {
        udp_hdr->source = htons(config.custom_source->port);
    } else {
        udp_hdr->source = htons(packet.src_port); // Or use ephemeral port
    }

    udp_hdr->dest = htons(target.port);
    udp_hdr->len = htons(sizeof(struct udphdr) + packet.payload.size());
    udp_hdr->check = 0;

    // Copy payload
    memcpy(packet_buffer.data() + sizeof(struct ip) + sizeof(struct udphdr),
        packet.payload.data(), packet.payload.size());

    // Calculate UDP checksum
    udp_hdr->check = udp_checksum(ip_hdr, udp_hdr, packet.payload.data(), packet.payload.size());

    // Send packet
    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr = ip_hdr->ip_dst;

    ssize_t sent = sendto(sock, packet_buffer.data(), packet_size, 0,
        (struct sockaddr*)&dest_addr, sizeof(dest_addr));

    if (sent < 0) {
        std::cerr << "Failed to send raw packet: " << strerror(errno) << std::endl;
        close(sock);
        return false;
    }

    if (config.verbose) {
        char src_ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ip_hdr->ip_src, src_ip_str, INET_ADDRSTRLEN);

        std::cout << "Sent " << sent << " bytes (raw) from "
                  << src_ip_str << ":" << ntohs(udp_hdr->source)
                  << " -> " << target.ip << ":" << target.port << std::endl;
    }

    close(sock);
    return true;
}

// Send UDP packet using normal sockets
bool sendUDPPacketNormal(const PacketInfo& packet, const Target& target, const ReplayConfig& config)
{
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        std::cerr << "Failed to create socket: " << strerror(errno) << std::endl;
        return false;
    }

    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(target.port);

    if (inet_pton(AF_INET, target.ip.c_str(), &dest_addr.sin_addr) <= 0) {
        std::cerr << "Invalid target IP: " << target.ip << std::endl;
        close(sock);
        return false;
    }

    // Send the packet
    ssize_t sent = sendto(sock, packet.payload.data(), packet.payload.size(), 0,
        (struct sockaddr*)&dest_addr, sizeof(dest_addr));

    if (sent < 0) {
        std::cerr << "Failed to send packet: " << strerror(errno) << std::endl;
        close(sock);
        return false;
    }

    if (config.verbose) {
        std::cout << "Sent " << sent << " bytes from interface"
                  << " (originally " << packet.src_ip << ":" << packet.src_port
                  << " -> " << packet.dst_ip << ":" << packet.dst_port << ")"
                  << " -> " << target.ip << ":" << target.port << std::endl;
    }

    close(sock);
    return true;
}

// Send UDP packet (dispatcher)
bool sendUDPPacket(const PacketInfo& packet, const Target& target, const ReplayConfig& config)
{
    if (config.source_mode == PRESERVE_ORIGINAL || config.source_mode == SPOOF_CUSTOM) {
        return sendUDPPacketRaw(packet, target, config);
    } else {
        return sendUDPPacketNormal(packet, target, config);
    }
}

// Replay packets from PCAP file
void replayPCAP(const ReplayConfig& config)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_offline(config.pcap_file.c_str(), errbuf);

    if (pcap == nullptr) {
        std::cerr << "Error opening pcap file: " << errbuf << std::endl;
        return;
    }

    struct pcap_pkthdr* header;
    const u_char* packet_data;

    std::vector<PacketInfo> packets_to_replay;

    // First pass: collect matching packets
    while (pcap_next_ex(pcap, &header, &packet_data) == 1) {
        PacketInfo packet_info;

        if (extractUDPPacket(packet_data, header, packet_info)) {
            if (matchesAnyFilter(packet_info, config.filters)) {
                packets_to_replay.push_back(packet_info);

                if (config.packet_count > 0 && packets_to_replay.size() >= static_cast<size_t>(config.packet_count)) {
                    break;
                }
            }
        }
    }

    pcap_close(pcap);

    std::cout << "Found " << packets_to_replay.size() << " matching UDP packets to replay" << std::endl;

    if (packets_to_replay.empty()) {
        return;
    }

    // Replay packets
    auto start_time = std::chrono::steady_clock::now();
    struct timeval first_packet_time = packets_to_replay[0].timestamp;

    for (size_t i = 0; i < packets_to_replay.size(); ++i) {
        const auto& packet = packets_to_replay[i];

        // Handle timing
        if (config.replay_speed == ORIGINAL_SPEED && i > 0) {
            // Calculate delay from original capture
            double delay = (packet.timestamp.tv_sec - first_packet_time.tv_sec) + (packet.timestamp.tv_usec - first_packet_time.tv_usec) / 1000000.0;

            // Apply rate multiplier
            delay /= config.rate_multiplier;

            // Wait until it's time to send this packet
            auto target_time = start_time + std::chrono::microseconds(static_cast<long>(delay * 1000000));
            std::this_thread::sleep_until(target_time);
        } else if (config.replay_speed == CONSTANT_RATE) {
            // Fixed rate
            if (i > 0) {
                std::this_thread::sleep_for(
                    std::chrono::microseconds(static_cast<long>(1000000.0 / config.rate_multiplier)));
            }
        }
        // MAX_SPEED = no delay

        // Send to target(s)
        size_t target_index = i % config.targets.size(); // Round-robin
        sendUDPPacket(packet, config.targets[target_index], config);
    }

    std::cout << "Replay completed!" << std::endl;
}

void showUsage(const char* program_name)
{
    std::cout << "Usage: " << program_name << " [options]" << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  -f, --file <pcap_file>        PCAP file to replay (required)" << std::endl;
    std::cout << "  -t, --target <ip:port>        Target for replayed packets (required, can be repeated)" << std::endl;
    std::cout << "\nFiltering Options:" << std::endl;
    std::cout << "  --filter <filter>             Filter packets (format: src:port->dst:port)" << std::endl;
    std::cout << "  --filter-src <ip>             Filter by source IP" << std::endl;
    std::cout << "  --filter-src-port <ports>     Filter by source port(s) (e.g., 53,123,514 or 8000-8999)" << std::endl;
    std::cout << "  --filter-dst <ip>             Filter by destination IP" << std::endl;
    std::cout << "  --filter-dst-port <ports>     Filter by destination port(s) (e.g., 53,123,514 or 8000-8999)" << std::endl;
    std::cout << "  --filter-protocol <proto>     Filter by protocol (dns, dhcp, ntp, syslog, snmp)" << std::endl;
    std::cout << "\nSource IP Options:" << std::endl;
    std::cout << "  --source-mode <mode>          Source mode: interface, preserve, custom (default: interface)" << std::endl;
    std::cout << "  --custom-source <ip:port>     Custom source IP:port (requires --source-mode custom)" << std::endl;
    std::cout << "\nTiming Options:" << std::endl;
    std::cout << "  --speed <mode>                Replay speed: original, constant, max (default: original)" << std::endl;
    std::cout << "  --rate <multiplier>           Rate multiplier (default: 1.0)" << std::endl;
    std::cout << "\nGeneral Options:" << std::endl;
    std::cout << "  -n, --count <packets>         Number of packets to replay (default: all)" << std::endl;
    std::cout << "  -v, --verbose                 Verbose output" << std::endl;
    std::cout << "  -h, --help                    Show this help" << std::endl;
    std::cout << "\nPort Specification:" << std::endl;
    std::cout << "  Single port:      53" << std::endl;
    std::cout << "  Multiple ports:   53,123,514" << std::endl;
    std::cout << "  Port range:       8000-8999" << std::endl;
    std::cout << "  Mixed:            53,123,8000-8999" << std::endl;
    std::cout << "\nFilter format: [src_ip]:[src_port]->[dst_ip]:[dst_port] (use * for any)" << std::endl;
    std::cout << "\nExamples:" << std::endl;
    std::cout << "  # Replay all DNS traffic to new server" << std::endl;
    std::cout << "  " << program_name << " -f capture.pcap --filter-dst-port 53 --target 10.0.0.5:53" << std::endl;
    std::cout << "\n  # Replay multiple protocols" << std::endl;
    std::cout << "  " << program_name << " -f capture.pcap --filter-dst-port 53,123,514 --target 10.0.0.5:9999" << std::endl;
    std::cout << "\n  # Replay with original source IPs (requires root)" << std::endl;
    std::cout << "  " << program_name << " -f capture.pcap --filter-protocol dns --source-mode preserve --target 10.0.0.5:53" << std::endl;
    std::cout << "\n  # Custom source spoofing" << std::endl;
    std::cout << "  " << program_name << " -f capture.pcap --filter-dst-port 53 --source-mode custom --custom-source 192.168.1.100:12345 --target 10.0.0.5:53" << std::endl;
}

int main(int argc, char* argv[])
{
    ReplayConfig config;

    static struct option long_options[] = {
        { "file", required_argument, 0, 'f' },
        { "target", required_argument, 0, 't' },
        { "filter", required_argument, 0, 0 },
        { "filter-src", required_argument, 0, 0 },
        { "filter-src-port", required_argument, 0, 0 },
        { "filter-dst", required_argument, 0, 0 },
        { "filter-dst-port", required_argument, 0, 0 },
        { "filter-protocol", required_argument, 0, 0 },
        { "source-mode", required_argument, 0, 0 },
        { "custom-source", required_argument, 0, 0 },
        { "speed", required_argument, 0, 0 },
        { "rate", required_argument, 0, 0 },
        { "count", required_argument, 0, 'n' },
        { "verbose", no_argument, 0, 'v' },
        { "help", no_argument, 0, 'h' },
        { 0, 0, 0, 0 }
    };

    int opt;
    int option_index = 0;

    while ((opt = getopt_long(argc, argv, "f:t:n:vh", long_options, &option_index)) != -1) {
        switch (opt) {
        case 0: {
            std::string option_name = long_options[option_index].name;

            if (option_name == "filter") {
                ReplayFilter filter;
                if (parseFilter(optarg, filter)) {
                    config.filters.push_back(filter);
                } else {
                    std::cerr << "Invalid filter format: " << optarg << std::endl;
                    return 1;
                }
            } else if (option_name == "filter-src") {
                ReplayFilter filter;
                filter.src_ip = optarg;
                config.filters.push_back(filter);
            } else if (option_name == "filter-src-port") {
                ReplayFilter filter;
                if (!parsePortSpec(optarg, filter.src_ports, filter.src_port_ranges)) {
                    std::cerr << "Invalid source port specification: " << optarg << std::endl;
                    return 1;
                }
                config.filters.push_back(filter);
            } else if (option_name == "filter-dst") {
                ReplayFilter filter;
                filter.dst_ip = optarg;
                config.filters.push_back(filter);
            } else if (option_name == "filter-dst-port") {
                ReplayFilter filter;
                if (!parsePortSpec(optarg, filter.dst_ports, filter.dst_port_ranges)) {
                    std::cerr << "Invalid destination port specification: " << optarg << std::endl;
                    return 1;
                }
                config.filters.push_back(filter);
            } else if (option_name == "filter-protocol") {
                ReplayFilter filter;
                filter.protocol = parseProtocol(optarg);
                if (filter.protocol == PROTO_ANY) {
                    std::cerr << "Unknown protocol: " << optarg << std::endl;
                    std::cerr << "Supported protocols: dns, dhcp, ntp, syslog, snmp" << std::endl;
                    return 1;
                }
                config.filters.push_back(filter);
            } else if (option_name == "source-mode") {
                std::string mode_str = optarg;
                if (mode_str == "interface") {
                    config.source_mode = USE_INTERFACE;
                } else if (mode_str == "preserve") {
                    config.source_mode = PRESERVE_ORIGINAL;
                } else if (mode_str == "custom") {
                    config.source_mode = SPOOF_CUSTOM;
                } else {
                    std::cerr << "Invalid source mode: " << mode_str << std::endl;
                    std::cerr << "Valid modes: interface, preserve, custom" << std::endl;
                    return 1;
                }
            } else if (option_name == "custom-source") {
                CustomSource source;
                if (parseCustomSource(optarg, source)) {
                    config.custom_source = source;
                } else {
                    std::cerr << "Invalid custom source format: " << optarg << std::endl;
                    return 1;
                }
            } else if (option_name == "speed") {
                std::string speed_str = optarg;
                if (speed_str == "original") {
                    config.replay_speed = ORIGINAL_SPEED;
                } else if (speed_str == "constant") {
                    config.replay_speed = CONSTANT_RATE;
                } else if (speed_str == "max") {
                    config.replay_speed = MAX_SPEED;
                } else {
                    std::cerr << "Invalid speed mode: " << speed_str << std::endl;
                    return 1;
                }
            } else if (option_name == "rate") {
                config.rate_multiplier = std::stod(optarg);
            }
            break;
        }

        case 'f':
            config.pcap_file = optarg;
            break;

        case 't': {
            Target target;
            if (parseTarget(optarg, target)) {
                config.targets.push_back(target);
            } else {
                std::cerr << "Invalid target format: " << optarg << std::endl;
                return 1;
            }
            break;
        }

        case 'n':
            config.packet_count = std::stoi(optarg);
            break;

        case 'v':
            config.verbose = true;
            break;

        case 'h':
            showUsage(argv[0]);
            return 0;

        default:
            showUsage(argv[0]);
            return 1;
        }
    }

    // Validate required options
    if (config.pcap_file.empty()) {
        std::cerr << "Error: PCAP file is required" << std::endl;
        showUsage(argv[0]);
        return 1;
    }

    if (config.targets.empty()) {
        std::cerr << "Error: At least one target is required" << std::endl;
        showUsage(argv[0]);
        return 1;
    }

    // Validate source mode requirements
    if (config.source_mode == SPOOF_CUSTOM && !config.custom_source) {
        std::cerr << "Error: Custom source mode requires --custom-source option" << std::endl;
        return 1;
    }

    // Check if PCAP file exists
    if (!fs::exists(config.pcap_file)) {
        std::cerr << "Error: PCAP file does not exist: " << config.pcap_file << std::endl;
        return 1;
    }

    // Display configuration
    std::cout << "UDP Packet Replayer" << std::endl;
    std::cout << "===================" << std::endl;
    std::cout << "PCAP file: " << config.pcap_file << std::endl;
    std::cout << "Targets: ";
    for (const auto& target : config.targets) {
        std::cout << target.ip << ":" << target.port << " ";
    }
    std::cout << std::endl;

    if (!config.filters.empty()) {
        std::cout << "Filters: " << config.filters.size() << " active" << std::endl;
    }

    std::cout << "Replay speed: ";
    switch (config.replay_speed) {
    case ORIGINAL_SPEED:
        std::cout << "original";
        break;
    case CONSTANT_RATE:
        std::cout << "constant (" << config.rate_multiplier << " pps)";
        break;
    case MAX_SPEED:
        std::cout << "maximum";
        break;
    }
    std::cout << std::endl;

    // Start replay
    replayPCAP(config);

    return 0;
}