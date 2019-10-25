#pragma once

#include <tins/tins.h>
#include <iostream>
#include <sstream>

const std::string kNetworkInterface("enx5cf7e68b298b");
const std::string kServerIP("192.168.1.100");
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