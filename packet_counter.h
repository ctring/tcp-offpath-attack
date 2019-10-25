#include <atomic>
#include <thread>
#include <tins/tins.h>

class PacketCounter {
public:
    PacketCounter(const std::string& iface, const std::string& filter);
    ~PacketCounter();
    void startCounting();
    int stopCounting();

private:
    void run();

    Tins::Sniffer* sniffer_;
    std::atomic<int> counter_;
    std::atomic<bool> counting_;
    std::thread runner_;
};