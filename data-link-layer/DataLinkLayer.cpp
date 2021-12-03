//
// Created by Zs on 2021/12/2.
//

#include "DataLinkLayer.h"

//std::mutex tex_;

DataLinkLayer::DataLinkLayer(const uint8_t *src_mac, const uint8_t *dst_mac) {
    for (int i = 0; i < 6; i++) this->src_mac_[i] = src_mac[i];
    for (int i = 0; i < 6; i++) this->dst_mac_[i] = dst_mac[i];

    if (pcap_findalldevs(&alldevs_, error_buffer_) == -1) {
        printf("%s\n", error_buffer_);
        exit(-1);
    }


    /* Print the list of all network adapter information */
    for (pcap_if_t *d = alldevs_; d; d = d->next) {
        printf("%d. %s", ++drive_nums_, d->name);
        if (d->description)
            printf(" kkk(%s)\n", d->description);
        else
            printf(" (No description available)\n");
    }

    if (drive_nums_ == 0) {
        printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
        exit(-1);
    }

    printf("Enter the interface number (1-%d):", drive_nums_);
    scanf("%d", &drive_selected_);
    if (drive_selected_ < 1 || drive_selected_ > drive_nums_) {
        printf("\nInterface number out of range.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs_);
        exit(-1);
    }

    /* Jump to the selected adapter */
    //int i = drive_selected_;
    pcap_if_t *dev = alldevs_ + drive_selected_;
    //for(int i=0;i<)
    //for (p = alldevs, temp_int = 0;  < drive_selected_ - 1; temp_drive = temp_drive->next, temp_pointer++);

    /* Open the adapter */
    if ((dev_handle_ = pcap_open_live(dev->name, // name of the device
                                      65536, // portion of the packet to capture.65536 grants that the whole packet will be captured on/// all the MACs.
                                      1, // promiscuous mode
                                      1000, // read timeout
                                      error_buffer_ // error buffer
    )) == nullptr) {
        printf("\nUnable to open the adapter. %s is not supported by WinPcap\n");
        /* Free the device list */
        pcap_freealldevs(alldevs_);
        exit(-1);
    }


    /* Check the link layer. We support only Ethernet for simplicity. */
    if (pcap_datalink(dev_handle_) != DLT_EN10MB) {
        printf("\nThis program works only on Ethernet networks.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs_);
        exit(-1);
    }

}

void DataLinkLayer::data_loader(const uint8_t *data_to_send) {
    if (data_to_send == nullptr) {
        printf("load file data!\n");
        FILE *fp = fopen("..\\test.txt", "rb");
        fseek(fp, 0, SEEK_END);
        data_length_ = ftell(fp);
        printf("length: %d\n", data_length_);
        fseek(fp, 0, SEEK_SET);
        data_ = (u_int8_t *) malloc(data_length_ * sizeof(u_int8_t));
        fread(data_, sizeof(u_int8_t), data_length_, fp);
        fclose(fp);
    } else {
        data_length_ = sizeof(data_to_send);
        data_ = (uint8_t *) data_to_send;
    }

}

void DataLinkLayer::generate_packet() {
    int status = 0;
    //std::string cwd(getcwd(NULL,0));
    //cwd = cwd.substr(0,cwd.rfind('\\'));
    //chdir(cwd.c_str());

    uint8_t buffer[PACKET_MAX_SIZE];
    memset(buffer, 0, sizeof(buffer));
    while (!if_send_end_) {
        size_of_packet_ = 0;
        load_ethernet_header(buffer);
        //status = load_ethernet_data(buffer + sizeof(ethernet_header), fp);
        status = load_ethernet_data(buffer + sizeof(ethernet_header));
        if (status == -1) {
            printf("load data error!\n");
            exit(-1);
        }
        while (send_queue_.size() > QUEUE_MAX_SIZE) {
            printf("send queue full!\n");
        }
        tex_->lock();
        auto new_pack = (u_int8_t *) malloc(size_of_packet_);
        memcpy(new_pack, buffer, size_of_packet_);
        ethernet_packet packet = {new_pack, size_of_packet_};
        send_queue_.push(packet);
        tex_->unlock();
        Sleep(SLEEP_TIME);
    }
}

void DataLinkLayer::send_packet() {
    while (!if_send_end_ || !send_queue_.empty()) {
        while (send_queue_.empty()) {
            printf("send queue is empty!\n");
        }
        tex_->lock();
        ethernet_packet packet = send_queue_.front();
        send_queue_.pop();
        int status = pcap_sendpacket(dev_handle_, (const u_char *) packet.packet, (int) packet.packet_size);
        if (status == 0) {
            printf("%d packets has sent\n", ++packet_has_sent_);
        } else {
            printf("send packet %d error! Error code is %d\n", ++packet_has_sent_, status);
        }
        free(packet.packet);
        tex_->unlock();
        Sleep(SLEEP_TIME);
    }
    pcap_close(dev_handle_);
}

void DataLinkLayer::load_ethernet_header(u_int8_t *buffer) {
    auto hdr = (struct ethernet_header *) buffer;
    // add destination and source mac address
    for (int i = 0; i < 6; i++) {
        hdr->dst_mac[i] = dst_mac_[i];
        hdr->src_mac[i] = src_mac_[i];
    }
    // add source typy
    hdr->ethernet_type = ETHERNET_TYPE;

    // caculate the size of packet now
    size_of_packet_ += sizeof(ethernet_header);
}

int DataLinkLayer::load_ethernet_data(u_int8_t *buffer) {
    int size_of_data = 0;
    memset(packet_data_, 0, sizeof(packet_data_));
    while (size_of_data < PACKET_DATA_MAX_SIZE && data_pointer_ < data_length_) {
        packet_data_[size_of_data++] = data_[data_pointer_++];
    }
    if (data_pointer_ >= data_length_) {
        if_send_end_ = true;
    }
    if (size_of_data < 46 || size_of_data > 1500) {
        printf("Size of data is not satisfied with condition!!!\n");
        printf("\n size of data is : %d\n", size_of_data);
        return -1;
    }
    //printf("%d\n", crc);
    int i;
    for (i = 0; i < size_of_data; i++) {
        *(buffer + i) = packet_data_[i];
    }
    return 1;
}

void DataLinkLayer::run() {

    std::thread generate_thread([this]() -> auto { this->generate_packet(); });
    std::thread send_thread([this]() -> auto { this->send_packet(); });

    generate_thread.join();
    send_thread.join();
}
