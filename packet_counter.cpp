#include "packet_counter.h"

#include <iostream>
#include <chrono>

using namespace std::chrono_literals;

PacketCounter::PacketCounter(
        const std::string& iface, const std::string& filter) {
    Tins::SnifferConfiguration config;
    config.set_filter(filter);
    config.set_pcap_sniffing_method(pcap_dispatch);
    sniffer_ = new Tins::Sniffer(iface, config);
    runner_ = std::thread(&PacketCounter::run, this);
}

PacketCounter::~PacketCounter() {
    sniffer_->stop_sniff();
    runner_.join();
    delete sniffer_;
}

void PacketCounter::run() {
    sniffer_->sniff_loop(
        [this](const Tins::PDU& pdu) {
            if (counting_) {
                counter_++;
            }
            return true;
        }
    );
}

void PacketCounter::startCounting() {
    counter_ = 0;
    counting_ = true;
}

int PacketCounter::stopCounting() {
    counting_ = false;
    return counter_;
}
