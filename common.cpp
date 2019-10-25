#include "common.h"

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

