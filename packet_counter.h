#pragma once

#include <atomic>
#include <thread>
#include <tins/tins.h>

class PacketCounter {
public:
    static PacketCounter* instance();
    void startCounting();
    int stopCounting();

    ~PacketCounter();
private:
    PacketCounter(const std::string& iface, const std::string& filter);

    void run();

    Tins::Sniffer* sniffer_;
    std::atomic<int> counter_;
    std::atomic<bool> counting_;
    std::thread runner_;

    static PacketCounter* instance_;
};