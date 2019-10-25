#include <tins/tins.h>

using namespace Tins;

int main() {
    EthernetII eth;
    IP *ip = new IP();
    TCP *tcp = new TCP();

    ip->inner_pdu(tcp);
    eth.inner_pdu(ip);
}