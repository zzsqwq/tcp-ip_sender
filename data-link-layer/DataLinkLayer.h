//
// Created by Zs on 2021/12/2.
//

#ifndef ZS_SENDER_DATALINKLAYER_H
#define ZS_SENDER_DATALINKLAYER_H

// winpcap
#include<pcap.h>
// c++ header
#include<cstring>
#include<cmath>
#include<iostream>
#include<queue>
#include<vector>
#include<stack>
#include<mutex>
#include<thread>
#include<cstdio>
#include<cstdlib>
#include<unistd.h>
#include<direct.h>
// common
#include<macro.h>

#define HAVE_REMOTE

//ethernet header
struct ethernet_header {
    u_int8_t dst_mac[MAC_BYTE_LENGTH];
    u_int8_t src_mac[MAC_BYTE_LENGTH];
    u_int16_t ethernet_type;
};

struct ethernet_packet {
    u_int8_t *packet;
    int packet_size;
};


class DataLinkLayer {
public:
    void generate_packet();

    void send_packet(pcap_t *adhandle);

    void load_ethernet_header(u_int8_t *buffer);

    int load_ethernet_data(u_int8_t *buffer, FILE *fp);

    int second_load_data(u_int8_t *buffer, u_int8_t *filebuffer);

private:
    pcap_t *adhandle;
    pcap_if_t *alldevs;
    u_int8_t dst_mac[6] = {0xA0, 0xE7, 0x0B, 0xAE, 0x45, 0x1B};
    u_int8_t src_mac[6] = {0xA0, 0xE7, 0x0B, 0xAE, 0x45, 0x1B};
    bool if_send_end = false;
    std::queue<ethernet_packet> send_queue;
    std::mutex tex;

};


#endif //ZS_SENDER_DATALINKLAYER_H
