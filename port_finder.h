#pragma once

#include <tins/tins.h>
#include <chrono>

#include "common.h"

class PortFinder {
public:
    PortFinder(
            ConnectionID legitConn, 
            uint32_t legitLastSeq, 
            const std::string& victimIP);

    void setSyncDelayMs(std::chrono::milliseconds syncDelayMs);

    uint32_t find(uint32_t from, uint32_t to);

private:

    bool has_port(uint32_t from, uint32_t to);

    ConnectionID legitConn_;
    uint32_t legitLastSeq_;
    std::string victimIP_;
    Tins::PacketSender sender_;

    std::chrono::milliseconds syncDelayMs_;
};