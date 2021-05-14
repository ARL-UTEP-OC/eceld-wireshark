#include "packet_address_info.h"

packet_address_info::packet_address_info() {
    srcMACAddress = QString();
    dstMACAddress = QString();
    srcIPAddress = QString();
    dstIPAddress = QString();
    srcPort = QString();
    dstPort = QString();
    ingress = false;
    egress = false;
    bothDir = false;
}