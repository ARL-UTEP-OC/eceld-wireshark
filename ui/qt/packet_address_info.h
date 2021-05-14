#ifndef PACKET_ADDRESS_INFO_H
#define PACKET_ADDRESS_INFO_H

#include <QString>

class packet_address_info
{
public: 
    packet_address_info();
    QString srcMACAddress;
    QString dstMACAddress;
    QString srcIPAddress;
    QString dstIPAddress;
    QString srcPort;
    QString dstPort;
    bool ingress;
    bool egress;
    bool bothDir;

};

#endif //PACKET_ADDRESS_INFO_H