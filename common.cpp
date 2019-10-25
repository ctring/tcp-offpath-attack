#include "common.h"

#include <tins/tins.h>

bool has_packet(Tins::Sniffer& sniffer, time_t timeout_s) {
    auto fd = pcap_get_selectable_fd(sniffer.get_pcap_handle());
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(fd, &readfds);
    timeval tv;
    tv.tv_sec = timeout_s;
    tv.tv_usec = 0;
    auto rv = select(fd + 1, &readfds, nullptr, nullptr, &tv);
    return rv > 0;
}

Tins::IP make_packet(
        ConnectionID conn, std::string flags, uint32_t seq, std::string raw) {
    Tins::IP ipHeader = Tins::IP(conn.serverIP, conn.clientIP);
    Tins::TCP tcpHeader = Tins::TCP(conn.serverPort, conn.clientPort);
    for (auto c : flags) {
        switch (c) {
            case 'R': 
                tcpHeader.set_flag(Tins::TCP::Flags::RST, 1);
                break;
            case 'A':
                tcpHeader.set_flag(Tins::TCP::Flags::ACK, 1);
                break;
            case 'S':
                tcpHeader.set_flag(Tins::TCP::Flags::SYN, 1);
                break;
        }
    }
    tcpHeader.seq(seq);

    return ipHeader / tcpHeader / Tins::RawPDU(raw);
}