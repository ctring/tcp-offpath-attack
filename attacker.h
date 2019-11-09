#pragma once

#include <tins/tins.h>
#include <chrono>

#include "common.h"

class Attacker {
public:
    Attacker(
        ConnectionID legitConn, 
        uint32_t legitLastSeq, 
        const std::string& victimIP);

    std::chrono::milliseconds synchronizeClock();

    uint32_t find_port(uint32_t from, uint32_t to);

private:

    bool has_port(uint32_t from, uint32_t to);

    ConnectionID legitConn_;
    uint32_t legitLastSeq_;
    std::string victimIP_;
    uint32_t victimPort_;
    Tins::PacketSender sender_;

    std::chrono::milliseconds syncDelayMs_;
};