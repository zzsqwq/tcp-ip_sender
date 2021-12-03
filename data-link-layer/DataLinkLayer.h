//
// Created by Zs on 2021/12/2.
//

#ifndef ZS_SENDER_DATALINKLAYER_H
#define ZS_SENDER_DATALINKLAYER_H
#define HAVE_REMOTE
// c++ header
#include<stdio.h>
#include<stdlib.h>
#include<cstring>
#include<cmath>
#include<iostream>
#include<queue>
#include<vector>
#include<stack>
#include<mutex>
#include<thread>
#include<unistd.h>
#include<direct.h>
// common
#include<macro.h>

// winpcap
#include<pcap.h>

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

    DataLinkLayer(uint8_t *src_mac, uint8_t *dst_mac);

    void generate_packet();

    void data_loader(const uint8_t *data_to_send = nullptr);

    void send_packet();

    void load_ethernet_header(u_int8_t *buffer);

    int load_ethernet_data(u_int8_t *buffer);

    void run();

    ~DataLinkLayer() = default;

private:
    pcap_t *dev_handle_;
    pcap_if_t *alldevs_;
    uint8_t *data_;
    uint8_t packet_data_[PACKET_DATA_MAX_SIZE];
    uint8_t data_length_;
    uint8_t data_pointer_;
    u_int8_t dst_mac_[6] = {0xA0, 0xE7, 0x0B, 0xAE, 0x45, 0x1B};
    u_int8_t src_mac_[6] = {0xA0, 0xE7, 0x0B, 0xAE, 0x45, 0x1B};
    bool if_send_end_ = false;
    int size_of_packet_ = 0;
    int packet_has_sent_ = 0;
    std::queue<ethernet_packet> send_queue_;
    std::mutex *tex_ = new std::mutex();
    char error_buffer_[PCAP_ERRBUF_SIZE];
    int drive_nums_{0};
    int drive_selected_ = 0;


};

#endif //ZS_SENDER_DATALINKLAYER_H
