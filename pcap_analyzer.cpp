#include <algorithm>
#include <arpa/inet.h>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <map>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <set>
#include <sstream>
#include <unordered_map>
#include <vector>

namespace fs = std::filesystem;

enum OutputFormat {
    FORMAT_TEXT,
    FORMAT_XML,
    FORMAT_JSON
};

struct PcapFileInfo {
    std::string filename;
    std::string filepath;
    time_t start_time;
    time_t end_time;
    size_t packet_count;
};

struct GapInfo {
    std::string file1;
    std::string file2;
    int gap_seconds;
    bool is_overlap;
};

struct ConnectionInfo {
    std::string src_ip;
    std::string dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    std::string protocol;
    size_t packet_count;
    size_t byte_count;
};

struct NetworkStats {
    std::unordered_map<std::string, size_t> src_ips;
    std::unordered_map<std::string, size_t> dst_ips;
    std::unordered_map<uint16_t, size_t> src_ports;
    std::unordered_map<uint16_t, size_t> dst_ports;
    std::unordered_map<std::string, size_t> protocols;
    std::unordered_map<std::string, ConnectionInfo> connections;
    size_t total_ipv4_packets;
    size_t total_ipv6_packets;
    size_t total_tcp_packets;
    size_t total_udp_packets;
    size_t total_other_packets;
};

// Global flag for IP analysis
bool analyze_ips = false;

// Convert timestamp to readable string
std::string timestampToString(time_t timestamp)
{
    char buffer[100];
    struct tm* tm_info = localtime(&timestamp);
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", tm_info);
    return std::string(buffer);
}

// Convert timestamp to ISO 8601 format for XML/JSON
std::string timestampToISO8601(time_t timestamp)
{
    char buffer[100];
    struct tm* tm_info = gmtime(&timestamp);
    strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ", tm_info);
    return std::string(buffer);
}

// Escape special characters for XML
std::string escapeXml(const std::string& str)
{
    std::string result;
    for (char c : str) {
        switch (c) {
        case '&':
            result += "&amp;";
            break;
        case '<':
            result += "&lt;";
            break;
        case '>':
            result += "&gt;";
            break;
        case '"':
            result += "&quot;";
            break;
        case '\'':
            result += "&apos;";
            break;
        default:
            result += c;
        }
    }
    return result;
}

// Escape special characters for JSON
std::string escapeJson(const std::string& str)
{
    std::string result;
    for (char c : str) {
        switch (c) {
        case '"':
            result += "\\\"";
            break;
        case '\\':
            result += "\\\\";
            break;
        case '\b':
            result += "\\b";
            break;
        case '\f':
            result += "\\f";
            break;
        case '\n':
            result += "\\n";
            break;
        case '\r':
            result += "\\r";
            break;
        case '\t':
            result += "\\t";
            break;
        default:
            result += c;
        }
    }
    return result;
}

// Get top N entries from a map
template <typename K, typename V>
std::vector<std::pair<K, V>> getTopN(const std::unordered_map<K, V>& m, size_t n)
{
    std::vector<std::pair<K, V>> vec(m.begin(), m.end());
    std::partial_sort(vec.begin(),
        vec.begin() + std::min(n, vec.size()),
        vec.end(),
        [](const auto& a, const auto& b) { return a.second > b.second; });
    vec.resize(std::min(n, vec.size()));
    return vec;
}

// Analyze packet for IP information
void analyzePacket(const u_char* packet, struct pcap_pkthdr* header, NetworkStats& stats)
{
    // Ethernet header is typically 14 bytes
    const int ethernet_header_len = 14;

    if (header->caplen < ethernet_header_len)
        return;

    // Get Ethernet type
    uint16_t ether_type = ntohs(*((uint16_t*)(packet + 12)));

    std::string src_ip, dst_ip, protocol;
    uint16_t src_port = 0, dst_port = 0;

    // Check if it's IPv4
    if (ether_type == 0x0800) {
        const struct ip* ip_header = (struct ip*)(packet + ethernet_header_len);

        if (header->caplen < ethernet_header_len + sizeof(struct ip))
            return;

        char src_addr[INET_ADDRSTRLEN];
        char dst_addr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip_header->ip_src), src_addr, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_header->ip_dst), dst_addr, INET_ADDRSTRLEN);

        src_ip = src_addr;
        dst_ip = dst_addr;
        stats.total_ipv4_packets++;

        int ip_header_len = ip_header->ip_hl * 4;

        // Check protocol
        if (ip_header->ip_p == IPPROTO_TCP) {
            protocol = "TCP";
            stats.total_tcp_packets++;

            if (header->caplen >= ethernet_header_len + ip_header_len + sizeof(struct tcphdr)) {
                const struct tcphdr* tcp_header = (struct tcphdr*)(packet + ethernet_header_len + ip_header_len);
                src_port = ntohs(tcp_header->source);
                dst_port = ntohs(tcp_header->dest);
            }
        } else if (ip_header->ip_p == IPPROTO_UDP) {
            protocol = "UDP";
            stats.total_udp_packets++;

            if (header->caplen >= ethernet_header_len + ip_header_len + sizeof(struct udphdr)) {
                const struct udphdr* udp_header = (struct udphdr*)(packet + ethernet_header_len + ip_header_len);
                src_port = ntohs(udp_header->source);
                dst_port = ntohs(udp_header->dest);
            }
        } else if (ip_header->ip_p == IPPROTO_ICMP) {
            protocol = "ICMP";
            stats.total_other_packets++;
        } else {
            protocol = "Other-IPv4";
            stats.total_other_packets++;
        }
    }
    // Check if it's IPv6
    else if (ether_type == 0x86DD) {
        const struct ip6_hdr* ip6_header = (struct ip6_hdr*)(packet + ethernet_header_len);

        if (header->caplen < ethernet_header_len + sizeof(struct ip6_hdr))
            return;

        char src_addr[INET6_ADDRSTRLEN];
        char dst_addr[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &(ip6_header->ip6_src), src_addr, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &(ip6_header->ip6_dst), dst_addr, INET6_ADDRSTRLEN);

        src_ip = src_addr;
        dst_ip = dst_addr;
        stats.total_ipv6_packets++;

        // Check next header for protocol
        uint8_t next_header = ip6_header->ip6_nxt;

        if (next_header == IPPROTO_TCP) {
            protocol = "TCP";
            stats.total_tcp_packets++;

            if (header->caplen >= ethernet_header_len + sizeof(struct ip6_hdr) + sizeof(struct tcphdr)) {
                const struct tcphdr* tcp_header = (struct tcphdr*)(packet + ethernet_header_len + sizeof(struct ip6_hdr));
                src_port = ntohs(tcp_header->source);
                dst_port = ntohs(tcp_header->dest);
            }
        } else if (next_header == IPPROTO_UDP) {
            protocol = "UDP";
            stats.total_udp_packets++;

            if (header->caplen >= ethernet_header_len + sizeof(struct ip6_hdr) + sizeof(struct udphdr)) {
                const struct udphdr* udp_header = (struct udphdr*)(packet + ethernet_header_len + sizeof(struct ip6_hdr));
                src_port = ntohs(udp_header->source);
                dst_port = ntohs(udp_header->dest);
            }
        } else if (next_header == IPPROTO_ICMPV6) {
            protocol = "ICMPv6";
            stats.total_other_packets++;
        } else {
            protocol = "Other-IPv6";
            stats.total_other_packets++;
        }
    } else {
        return; // Not IP packet
    }

    // Update statistics
    if (!src_ip.empty()) {
        stats.src_ips[src_ip]++;
        stats.dst_ips[dst_ip]++;
        stats.protocols[protocol]++;

        if (src_port > 0) {
            stats.src_ports[src_port]++;
            stats.dst_ports[dst_port]++;
        }

        // Create connection key
        std::stringstream conn_key;
        conn_key << src_ip << ":" << src_port << "->" << dst_ip << ":" << dst_port << "/" << protocol;
        std::string key = conn_key.str();

        if (stats.connections.find(key) == stats.connections.end()) {
            ConnectionInfo conn;
            conn.src_ip = src_ip;
            conn.dst_ip = dst_ip;
            conn.src_port = src_port;
            conn.dst_port = dst_port;
            conn.protocol = protocol;
            conn.packet_count = 0;
            conn.byte_count = 0;
            stats.connections[key] = conn;
        }

        stats.connections[key].packet_count++;
        stats.connections[key].byte_count += header->len;
    }
}

// Read pcap file and extract timing information (and optionally IP info)
bool analyzePcapFile(const std::string& filepath, PcapFileInfo& info, NetworkStats* network_stats = nullptr)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_offline(filepath.c_str(), errbuf);

    if (pcap == nullptr) {
        std::cerr << "Error opening pcap file " << filepath << ": " << errbuf << std::endl;
        return false;
    }

    struct pcap_pkthdr* header;
    const u_char* packet;

    info.start_time = 0;
    info.end_time = 0;
    info.packet_count = 0;

    // Read all packets to get start and end times
    while (pcap_next_ex(pcap, &header, &packet) == 1) {
        if (info.packet_count == 0) {
            // First packet - set start time
            info.start_time = header->ts.tv_sec;
            info.end_time = header->ts.tv_sec;
        } else {
            // Update end time
            if (header->ts.tv_sec < info.start_time) {
                info.start_time = header->ts.tv_sec;
            }
            if (header->ts.tv_sec > info.end_time) {
                info.end_time = header->ts.tv_sec;
            }
        }
        info.packet_count++;

        // Analyze packet for IP info if requested
        if (analyze_ips && network_stats != nullptr) {
            analyzePacket(packet, header, *network_stats);
        }
    }

    pcap_close(pcap);
    return info.packet_count > 0;
}

// Output network statistics in text format
void outputNetworkStatsText(const NetworkStats& stats)
{
    std::cout << "\nNetwork Analysis Summary:" << std::endl;
    std::cout << std::string(100, '=') << std::endl;

    // Protocol distribution
    std::cout << "\nProtocol Distribution:" << std::endl;
    std::cout << std::string(50, '-') << std::endl;
    std::cout << "IPv4 packets: " << stats.total_ipv4_packets << std::endl;
    std::cout << "IPv6 packets: " << stats.total_ipv6_packets << std::endl;
    std::cout << "TCP packets:  " << stats.total_tcp_packets << std::endl;
    std::cout << "UDP packets:  " << stats.total_udp_packets << std::endl;
    std::cout << "Other:        " << stats.total_other_packets << std::endl;

    // Top source IPs
    std::cout << "\nTop 10 Source IP Addresses:" << std::endl;
    std::cout << std::string(50, '-') << std::endl;
    auto top_src_ips = getTopN(stats.src_ips, 10);
    for (const auto& [ip, count] : top_src_ips) {
        std::cout << std::left << std::setw(40) << ip << std::right << std::setw(10) << count << " packets" << std::endl;
    }

    // Top destination IPs
    std::cout << "\nTop 10 Destination IP Addresses:" << std::endl;
    std::cout << std::string(50, '-') << std::endl;
    auto top_dst_ips = getTopN(stats.dst_ips, 10);
    for (const auto& [ip, count] : top_dst_ips) {
        std::cout << std::left << std::setw(40) << ip << std::right << std::setw(10) << count << " packets" << std::endl;
    }

    // Top destination ports
    std::cout << "\nTop 10 Destination Ports:" << std::endl;
    std::cout << std::string(50, '-') << std::endl;
    auto top_dst_ports = getTopN(stats.dst_ports, 10);
    for (const auto& [port, count] : top_dst_ports) {
        std::cout << std::left << "Port " << std::setw(6) << port;

        // Add common service names
        switch (port) {
        case 20:
            std::cout << " (FTP-DATA)";
            break;
        case 21:
            std::cout << " (FTP)";
            break;
        case 22:
            std::cout << " (SSH)";
            break;
        case 23:
            std::cout << " (TELNET)";
            break;
        case 25:
            std::cout << " (SMTP)";
            break;
        case 53:
            std::cout << " (DNS)";
            break;
        case 80:
            std::cout << " (HTTP)";
            break;
        case 110:
            std::cout << " (POP3)";
            break;
        case 143:
            std::cout << " (IMAP)";
            break;
        case 443:
            std::cout << " (HTTPS)";
            break;
        case 445:
            std::cout << " (SMB)";
            break;
        case 3306:
            std::cout << " (MySQL)";
            break;
        case 3389:
            std::cout << " (RDP)";
            break;
        case 8080:
            std::cout << " (HTTP-Alt)";
            break;
        default:
            std::cout << "         ";
            break;
        }

        std::cout << std::right << std::setw(20) << count << " packets" << std::endl;
    }

    // Top connections
    std::cout << "\nTop 10 Connections (by packet count):" << std::endl;
    std::cout << std::string(100, '-') << std::endl;
    std::cout << std::left << std::setw(50) << "Connection"
              << std::setw(10) << "Protocol"
              << std::setw(15) << "Packets"
              << std::setw(15) << "Bytes" << std::endl;
    std::cout << std::string(100, '-') << std::endl;

    std::vector<std::pair<std::string, ConnectionInfo>> conn_vec;
    for (const auto& [key, conn] : stats.connections) {
        conn_vec.push_back({ key, conn });
    }
    std::sort(conn_vec.begin(), conn_vec.end(),
        [](const auto& a, const auto& b) { return a.second.packet_count > b.second.packet_count; });

    for (size_t i = 0; i < std::min(size_t(10), conn_vec.size()); i++) {
        const auto& conn = conn_vec[i].second;
        std::stringstream conn_str;
        conn_str << conn.src_ip << ":" << conn.src_port << " -> " << conn.dst_ip << ":" << conn.dst_port;

        std::cout << std::left << std::setw(50) << conn_str.str()
                  << std::setw(10) << conn.protocol
                  << std::setw(15) << conn.packet_count
                  << std::setw(15) << conn.byte_count << std::endl;
    }

    std::cout << std::string(100, '=') << std::endl;
}

// Output network statistics in XML format
void outputNetworkStatsXML(const NetworkStats& stats)
{
    std::cout << "  <network_analysis>" << std::endl;

    std::cout << "    <protocol_distribution>" << std::endl;
    std::cout << "      <ipv4_packets>" << stats.total_ipv4_packets << "</ipv4_packets>" << std::endl;
    std::cout << "      <ipv6_packets>" << stats.total_ipv6_packets << "</ipv6_packets>" << std::endl;
    std::cout << "      <tcp_packets>" << stats.total_tcp_packets << "</tcp_packets>" << std::endl;
    std::cout << "      <udp_packets>" << stats.total_udp_packets << "</udp_packets>" << std::endl;
    std::cout << "      <other_packets>" << stats.total_other_packets << "</other_packets>" << std::endl;
    std::cout << "    </protocol_distribution>" << std::endl;

    std::cout << "    <top_source_ips>" << std::endl;
    auto top_src_ips = getTopN(stats.src_ips, 10);
    for (const auto& [ip, count] : top_src_ips) {
        std::cout << "      <ip address=\"" << escapeXml(ip) << "\" packets=\"" << count << "\"/>" << std::endl;
    }
    std::cout << "    </top_source_ips>" << std::endl;

    std::cout << "    <top_destination_ips>" << std::endl;
    auto top_dst_ips = getTopN(stats.dst_ips, 10);
    for (const auto& [ip, count] : top_dst_ips) {
        std::cout << "      <ip address=\"" << escapeXml(ip) << "\" packets=\"" << count << "\"/>" << std::endl;
    }
    std::cout << "    </top_destination_ips>" << std::endl;

    std::cout << "    <top_destination_ports>" << std::endl;
    auto top_dst_ports = getTopN(stats.dst_ports, 10);
    for (const auto& [port, count] : top_dst_ports) {
        std::cout << "      <port number=\"" << port << "\" packets=\"" << count << "\"/>" << std::endl;
    }
    std::cout << "    </top_destination_ports>" << std::endl;

    std::cout << "    <top_connections>" << std::endl;
    std::vector<std::pair<std::string, ConnectionInfo>> conn_vec;
    for (const auto& [key, conn] : stats.connections) {
        conn_vec.push_back({ key, conn });
    }
    std::sort(conn_vec.begin(), conn_vec.end(),
        [](const auto& a, const auto& b) { return a.second.packet_count > b.second.packet_count; });

    for (size_t i = 0; i < std::min(size_t(10), conn_vec.size()); i++) {
        const auto& conn = conn_vec[i].second;
        std::cout << "      <connection>" << std::endl;
        std::cout << "        <source_ip>" << escapeXml(conn.src_ip) << "</source_ip>" << std::endl;
        std::cout << "        <source_port>" << conn.src_port << "</source_port>" << std::endl;
        std::cout << "        <destination_ip>" << escapeXml(conn.dst_ip) << "</destination_ip>" << std::endl;
        std::cout << "        <destination_port>" << conn.dst_port << "</destination_port>" << std::endl;
        std::cout << "        <protocol>" << conn.protocol << "</protocol>" << std::endl;
        std::cout << "        <packet_count>" << conn.packet_count << "</packet_count>" << std::endl;
        std::cout << "        <byte_count>" << conn.byte_count << "</byte_count>" << std::endl;
        std::cout << "      </connection>" << std::endl;
    }
    std::cout << "    </top_connections>" << std::endl;

    std::cout << "  </network_analysis>" << std::endl;
}

// Output network statistics in JSON format
void outputNetworkStatsJSON(const NetworkStats& stats)
{
    std::cout << "," << std::endl;
    std::cout << "  \"network_analysis\": {" << std::endl;

    std::cout << "    \"protocol_distribution\": {" << std::endl;
    std::cout << "      \"ipv4_packets\": " << stats.total_ipv4_packets << "," << std::endl;
    std::cout << "      \"ipv6_packets\": " << stats.total_ipv6_packets << "," << std::endl;
    std::cout << "      \"tcp_packets\": " << stats.total_tcp_packets << "," << std::endl;
    std::cout << "      \"udp_packets\": " << stats.total_udp_packets << "," << std::endl;
    std::cout << "      \"other_packets\": " << stats.total_other_packets << std::endl;
    std::cout << "    }," << std::endl;

    std::cout << "    \"top_source_ips\": [" << std::endl;
    auto top_src_ips = getTopN(stats.src_ips, 10);
    for (size_t i = 0; i < top_src_ips.size(); i++) {
        const auto& [ip, count] = top_src_ips[i];
        std::cout << "      {\"address\": \"" << escapeJson(ip) << "\", \"packets\": " << count << "}"
                  << (i < top_src_ips.size() - 1 ? "," : "") << std::endl;
    }
    std::cout << "    ]," << std::endl;

    std::cout << "    \"top_destination_ips\": [" << std::endl;
    auto top_dst_ips = getTopN(stats.dst_ips, 10);
    for (size_t i = 0; i < top_dst_ips.size(); i++) {
        const auto& [ip, count] = top_dst_ips[i];
        std::cout << "      {\"address\": \"" << escapeJson(ip) << "\", \"packets\": " << count << "}"
                  << (i < top_dst_ips.size() - 1 ? "," : "") << std::endl;
    }
    std::cout << "    ]," << std::endl;

    std::cout << "    \"top_destination_ports\": [" << std::endl;
    auto top_dst_ports = getTopN(stats.dst_ports, 10);
    for (size_t i = 0; i < top_dst_ports.size(); i++) {
        const auto& [port, count] = top_dst_ports[i];
        std::cout << "      {\"port\": " << port << ", \"packets\": " << count << "}"
                  << (i < top_dst_ports.size() - 1 ? "," : "") << std::endl;
    }
    std::cout << "    ]," << std::endl;

    std::cout << "    \"top_connections\": [" << std::endl;
    std::vector<std::pair<std::string, ConnectionInfo>> conn_vec;
    for (const auto& [key, conn] : stats.connections) {
        conn_vec.push_back({ key, conn });
    }
    std::sort(conn_vec.begin(), conn_vec.end(),
        [](const auto& a, const auto& b) { return a.second.packet_count > b.second.packet_count; });

    for (size_t i = 0; i < std::min(size_t(10), conn_vec.size()); i++) {
        const auto& conn = conn_vec[i].second;
        std::cout << "      {" << std::endl;
        std::cout << "        \"source_ip\": \"" << escapeJson(conn.src_ip) << "\"," << std::endl;
        std::cout << "        \"source_port\": " << conn.src_port << "," << std::endl;
        std::cout << "        \"destination_ip\": \"" << escapeJson(conn.dst_ip) << "\"," << std::endl;
        std::cout << "        \"destination_port\": " << conn.dst_port << "," << std::endl;
        std::cout << "        \"protocol\": \"" << conn.protocol << "\"," << std::endl;
        std::cout << "        \"packet_count\": " << conn.packet_count << "," << std::endl;
        std::cout << "        \"byte_count\": " << conn.byte_count << std::endl;
        std::cout << "      }" << (i < std::min(size_t(10), conn_vec.size()) - 1 ? "," : "") << std::endl;
    }
    std::cout << "    ]" << std::endl;

    std::cout << "  }" << std::endl;
}

// Output in text format
void outputText(const std::vector<PcapFileInfo>& pcap_files,
    time_t overall_start, time_t overall_end,
    size_t total_packets, const std::vector<GapInfo>& gaps,
    const NetworkStats* network_stats = nullptr)
{

    // Display results
    std::cout << "\n"
              << std::string(100, '=') << std::endl;
    std::cout << "PCAP Files Sorted by Start Time:" << std::endl;
    std::cout << std::string(100, '=') << std::endl;

    std::cout << std::left << std::setw(30) << "Filename"
              << std::setw(25) << "Start Time"
              << std::setw(25) << "End Time"
              << std::setw(10) << "Duration"
              << std::setw(10) << "Packets" << std::endl;
    std::cout << std::string(100, '-') << std::endl;

    for (const auto& info : pcap_files) {
        int duration = info.end_time - info.start_time;
        int hours = duration / 3600;
        int minutes = (duration % 3600) / 60;
        int seconds = duration % 60;

        std::stringstream duration_str;
        duration_str << hours << "h " << minutes << "m " << seconds << "s";

        std::cout << std::left << std::setw(30) << info.filename
                  << std::setw(25) << timestampToString(info.start_time)
                  << std::setw(25) << timestampToString(info.end_time)
                  << std::setw(10) << duration_str.str()
                  << std::setw(10) << info.packet_count << std::endl;
    }

    std::cout << std::string(100, '=') << std::endl;
    std::cout << "Total files analyzed: " << pcap_files.size() << std::endl;

    // Display overall statistics
    std::cout << "\nOverall Capture Statistics:" << std::endl;
    std::cout << std::string(100, '-') << std::endl;

    int overall_duration = overall_end - overall_start;
    int hours = overall_duration / 3600;
    int minutes = (overall_duration % 3600) / 60;
    int seconds = overall_duration % 60;

    std::cout << "Overall Start Time:     " << timestampToString(overall_start) << std::endl;
    std::cout << "Overall End Time:       " << timestampToString(overall_end) << std::endl;
    std::cout << "Total Duration:         " << hours << " hours, "
              << minutes << " minutes, " << seconds << " seconds" << std::endl;
    std::cout << "Total Packets Captured: " << total_packets << std::endl;

    // Display gap analysis
    if (!gaps.empty()) {
        std::cout << "\nTime Gap Analysis:" << std::endl;
        std::cout << std::string(100, '-') << std::endl;

        for (const auto& gap : gaps) {
            if (gap.gap_seconds > 0) {
                int gap_hours = gap.gap_seconds / 3600;
                int gap_minutes = (gap.gap_seconds % 3600) / 60;
                int gap_secs = gap.gap_seconds % 60;

                std::cout << "Gap between " << gap.file1
                          << " and " << gap.file2 << ": "
                          << gap_hours << "h " << gap_minutes << "m " << gap_secs << "s" << std::endl;
            } else if (gap.gap_seconds < 0) {
                std::cout << "Overlap between " << gap.file1
                          << " and " << gap.file2 << ": "
                          << -gap.gap_seconds << " seconds" << std::endl;
            }
        }
    }
    std::cout << std::string(100, '=') << std::endl;

    // Display network statistics if available
    if (analyze_ips && network_stats) {
        outputNetworkStatsText(*network_stats);
    }
}

// Output in XML format
void outputXML(const std::vector<PcapFileInfo>& pcap_files,
    time_t overall_start, time_t overall_end,
    size_t total_packets, const std::vector<GapInfo>& gaps,
    const NetworkStats* network_stats = nullptr)
{

    std::cout << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" << std::endl;
    std::cout << "<pcap_analysis>" << std::endl;

    // Overall statistics
    std::cout << "  <overall_statistics>" << std::endl;
    std::cout << "    <start_time>" << timestampToISO8601(overall_start) << "</start_time>" << std::endl;
    std::cout << "    <end_time>" << timestampToISO8601(overall_end) << "</end_time>" << std::endl;
    std::cout << "    <duration_seconds>" << (overall_end - overall_start) << "</duration_seconds>" << std::endl;
    std::cout << "    <total_packets>" << total_packets << "</total_packets>" << std::endl;
    std::cout << "    <total_files>" << pcap_files.size() << "</total_files>" << std::endl;
    std::cout << "  </overall_statistics>" << std::endl;

    // Individual files
    std::cout << "  <pcap_files>" << std::endl;
    for (const auto& info : pcap_files) {
        std::cout << "    <file>" << std::endl;
        std::cout << "      <filename>" << escapeXml(info.filename) << "</filename>" << std::endl;
        std::cout << "      <filepath>" << escapeXml(info.filepath) << "</filepath>" << std::endl;
        std::cout << "      <start_time>" << timestampToISO8601(info.start_time) << "</start_time>" << std::endl;
        std::cout << "      <end_time>" << timestampToISO8601(info.end_time) << "</end_time>" << std::endl;
        std::cout << "      <duration_seconds>" << (info.end_time - info.start_time) << "</duration_seconds>" << std::endl;
        std::cout << "      <packet_count>" << info.packet_count << "</packet_count>" << std::endl;
        std::cout << "    </file>" << std::endl;
    }
    std::cout << "  </pcap_files>" << std::endl;

    // Gap analysis
    if (!gaps.empty()) {
        std::cout << "  <gap_analysis>" << std::endl;
        for (const auto& gap : gaps) {
            std::cout << "    <gap>" << std::endl;
            std::cout << "      <file1>" << escapeXml(gap.file1) << "</file1>" << std::endl;
            std::cout << "      <file2>" << escapeXml(gap.file2) << "</file2>" << std::endl;
            std::cout << "      <type>" << (gap.is_overlap ? "overlap" : "gap") << "</type>" << std::endl;
            std::cout << "      <seconds>" << std::abs(gap.gap_seconds) << "</seconds>" << std::endl;
            std::cout << "    </gap>" << std::endl;
        }
        std::cout << "  </gap_analysis>" << std::endl;
    }

    // Network analysis if available
    if (analyze_ips && network_stats) {
        outputNetworkStatsXML(*network_stats);
    }

    std::cout << "</pcap_analysis>" << std::endl;
}

// Output in JSON format
void outputJSON(const std::vector<PcapFileInfo>& pcap_files,
    time_t overall_start, time_t overall_end,
    size_t total_packets, const std::vector<GapInfo>& gaps,
    const NetworkStats* network_stats = nullptr)
{

    std::cout << "{" << std::endl;

    // Overall statistics
    std::cout << "  \"overall_statistics\": {" << std::endl;
    std::cout << "    \"start_time\": \"" << timestampToISO8601(overall_start) << "\"," << std::endl;
    std::cout << "    \"end_time\": \"" << timestampToISO8601(overall_end) << "\"," << std::endl;
    std::cout << "    \"duration_seconds\": " << (overall_end - overall_start) << "," << std::endl;
    std::cout << "    \"total_packets\": " << total_packets << "," << std::endl;
    std::cout << "    \"total_files\": " << pcap_files.size() << std::endl;
    std::cout << "  }," << std::endl;

    // Individual files
    std::cout << "  \"pcap_files\": [" << std::endl;
    for (size_t i = 0; i < pcap_files.size(); ++i) {
        const auto& info = pcap_files[i];
        std::cout << "    {" << std::endl;
        std::cout << "      \"filename\": \"" << escapeJson(info.filename) << "\"," << std::endl;
        std::cout << "      \"filepath\": \"" << escapeJson(info.filepath) << "\"," << std::endl;
        std::cout << "      \"start_time\": \"" << timestampToISO8601(info.start_time) << "\"," << std::endl;
        std::cout << "      \"end_time\": \"" << timestampToISO8601(info.end_time) << "\"," << std::endl;
        std::cout << "      \"duration_seconds\": " << (info.end_time - info.start_time) << "," << std::endl;
        std::cout << "      \"packet_count\": " << info.packet_count << std::endl;
        std::cout << "    }" << (i < pcap_files.size() - 1 ? "," : "") << std::endl;
    }
    std::cout << "  ]";

    // Gap analysis
    if (!gaps.empty()) {
        std::cout << "," << std::endl;
        std::cout << "  \"gap_analysis\": [" << std::endl;
        for (size_t i = 0; i < gaps.size(); ++i) {
            const auto& gap = gaps[i];
            std::cout << "    {" << std::endl;
            std::cout << "      \"file1\": \"" << escapeJson(gap.file1) << "\"," << std::endl;
            std::cout << "      \"file2\": \"" << escapeJson(gap.file2) << "\"," << std::endl;
            std::cout << "      \"type\": \"" << (gap.is_overlap ? "overlap" : "gap") << "\"," << std::endl;
            std::cout << "      \"seconds\": " << std::abs(gap.gap_seconds) << std::endl;
            std::cout << "    }" << (i < gaps.size() - 1 ? "," : "") << std::endl;
        }
        std::cout << "  ]";
    }

    // Network analysis if available
    if (analyze_ips && network_stats) {
        outputNetworkStatsJSON(*network_stats);
    } else {
        std::cout << std::endl;
    }

    std::cout << "}" << std::endl;
}

// Display usage information
void showUsage(const char* program_name)
{
    std::cout << "Usage: " << program_name << " <directory_path> [options]" << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  -xml   Output results in XML format" << std::endl;
    std::cout << "  -json  Output results in JSON format" << std::endl;
    std::cout << "  -ips   Include IP address and port analysis" << std::endl;
    std::cout << "  (default is text format without IP analysis)" << std::endl;
    std::cout << "\nExamples:" << std::endl;
    std::cout << "  " << program_name << " /path/to/pcaps" << std::endl;
    std::cout << "  " << program_name << " /path/to/pcaps -ips" << std::endl;
    std::cout << "  " << program_name << " /path/to/pcaps -json -ips" << std::endl;
}

int main(int argc, char* argv[])
{
    if (argc < 2) {
        showUsage(argv[0]);
        return 1;
    }

    std::string directory_path = argv[1];
    OutputFormat output_format = FORMAT_TEXT;

    // Parse command line options
    for (int i = 2; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "-xml") {
            output_format = FORMAT_XML;
        } else if (arg == "-json") {
            output_format = FORMAT_JSON;
        } else if (arg == "-ips") {
            analyze_ips = true;
        } else {
            std::cerr << "Unknown option: " << arg << std::endl;
            showUsage(argv[0]);
            return 1;
        }
    }

    // Check if directory exists
    if (!fs::exists(directory_path) || !fs::is_directory(directory_path)) {
        std::cerr << "Error: '" << directory_path << "' is not a valid directory." << std::endl;
        return 1;
    }

    std::vector<PcapFileInfo> pcap_files;
    NetworkStats overall_network_stats = {};

    // Iterate through directory and find pcap files
    if (output_format == FORMAT_TEXT) {
        std::cout << "Scanning directory: " << directory_path << std::endl;
        std::cout << "Looking for pcap files..." << std::endl;
        if (analyze_ips) {
            std::cout << "IP analysis: ENABLED" << std::endl;
        }
        std::cout << std::endl;
    }

    for (const auto& entry : fs::directory_iterator(directory_path)) {
        if (entry.is_regular_file()) {
            std::string filename = entry.path().filename().string();
            std::string extension = entry.path().extension().string();

            // Check for common pcap extensions
            if (extension == ".pcap" || extension == ".cap" || extension == ".pcapng" || extension == ".dmp") {

                PcapFileInfo info;
                info.filename = filename;
                info.filepath = entry.path().string();

                if (output_format == FORMAT_TEXT) {
                    std::cout << "Analyzing: " << filename << "... ";
                }

                NetworkStats* stats_ptr = analyze_ips ? &overall_network_stats : nullptr;

                if (analyzePcapFile(info.filepath, info, stats_ptr)) {
                    pcap_files.push_back(info);
                    if (output_format == FORMAT_TEXT) {
                        std::cout << "Done (" << info.packet_count << " packets)" << std::endl;
                    }
                } else {
                    if (output_format == FORMAT_TEXT) {
                        std::cout << "Failed or empty" << std::endl;
                    }
                }
            }
        }
    }

    if (pcap_files.empty()) {
        if (output_format == FORMAT_TEXT) {
            std::cout << "\nNo valid pcap files found in the directory." << std::endl;
        }
        return 0;
    }

    // Sort pcap files by start time
    std::sort(pcap_files.begin(), pcap_files.end(),
        [](const PcapFileInfo& a, const PcapFileInfo& b) {
            return a.start_time < b.start_time;
        });

    // Calculate overall start and end times
    time_t overall_start = pcap_files[0].start_time;
    time_t overall_end = pcap_files[0].end_time;
    size_t total_packets = 0;

    for (const auto& info : pcap_files) {
        if (info.start_time < overall_start) {
            overall_start = info.start_time;
        }
        if (info.end_time > overall_end) {
            overall_end = info.end_time;
        }
        total_packets += info.packet_count;
    }

    // Calculate gaps
    std::vector<GapInfo> gaps;
    for (size_t i = 1; i < pcap_files.size(); i++) {
        int gap_seconds = pcap_files[i].start_time - pcap_files[i - 1].end_time;
        if (gap_seconds != 0) {
            GapInfo gap;
            gap.file1 = pcap_files[i - 1].filename;
            gap.file2 = pcap_files[i].filename;
            gap.gap_seconds = gap_seconds;
            gap.is_overlap = (gap_seconds < 0);
            gaps.push_back(gap);
        }
    }

    // Output results based on format
    switch (output_format) {
    case FORMAT_XML:
        outputXML(pcap_files, overall_start, overall_end, total_packets, gaps,
            analyze_ips ? &overall_network_stats : nullptr);
        break;
    case FORMAT_JSON:
        outputJSON(pcap_files, overall_start, overall_end, total_packets, gaps,
            analyze_ips ? &overall_network_stats : nullptr);
        break;
    case FORMAT_TEXT:
    default:
        outputText(pcap_files, overall_start, overall_end, total_packets, gaps,
            analyze_ips ? &overall_network_stats : nullptr);
        break;
    }

    return 0;
}