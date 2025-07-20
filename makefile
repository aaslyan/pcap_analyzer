CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2
LDFLAGS = -lpcap

TARGETS = pcap_analyzer udp_replayer
ANALYZER_SOURCE = pcap_analyzer.cpp
REPLAYER_SOURCE = udp_replayer.cpp

all: $(TARGETS)

pcap_analyzer: $(ANALYZER_SOURCE)
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)

udp_replayer: $(REPLAYER_SOURCE)
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGETS)

install: $(TARGETS)
	cp $(TARGETS) /usr/local/bin/

.PHONY: all clean install