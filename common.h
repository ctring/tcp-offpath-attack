#pragma once

#include <tins/tins.h>
#include <chrono>
#include <iostream>
#include <sstream>
#include <thread>

const std::string kNetworkInterface("virbr0");
const std::string kServerIP("192.168.122.3"); // ubuntu
const std::string kVictimIP("192.168.122.2");
const uint32_t kServerPort = 22;

struct ConnectionID{
    Tins::IPv4Address clientIP;
    uint32_t clientPort;
    Tins::IPv4Address serverIP;
    uint32_t serverPort;

    ConnectionID(
      const Tins::IPv4Address& clientIP, 
      uint32_t clientPort, 
      const Tins::IPv4Address& serverIP,
      uint32_t serverPort) :
        clientIP(clientIP), clientPort(clientPort), 
        serverIP(serverIP), serverPort(serverPort) {}

    ConnectionID() {}

    std::string toString() {
        std::stringstream ss;
        ss << "(" << clientIP << ":" << clientPort << " -> " 
           << serverIP << ":" << serverPort << ")";
        return ss.str();
    }
};

bool has_packet(Tins::Sniffer& sniffer, time_t timeout_s);
Tins::IP make_packet(
        ConnectionID connection, 
        std::string flags, 
        uint32_t seq, 
        std::string raw="X");

using namespace std::chrono;

// Aligns the clock at a full second plus a given milliseconds then returns the 
// time from epoch in milliseconds that the current thread slept until
inline milliseconds align_and_delay(milliseconds ms) {
    auto now = system_clock::now();
    auto s = duration_cast<seconds>(now.time_since_epoch()) + 1000ms + ms;
    std::this_thread::sleep_until(system_clock::time_point(s));
    return s;
}