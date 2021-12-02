#include<stdio.h>
#include<stdlib.h>

#define HAVE_REMOTE

#include<pcap.h>
#include<unistd.h>
#include <direct.h>
// c++ header
#include<cstring>
#include<cmath>
#include<iostream>
#include<queue>
#include<vector>
#include<stack>
#include<mutex>
#include<thread>

#pragma warning(disable:4996)

#define ETHERNET_TYPE 0x0800 //ipv4
#define MAX_SIZE 1530
#define DATA_MAX_SIZE 1300
#define MAC_BYTE_LENGTH 6
#define QUEUE_MAX_SIZE 100
#define SLEEP_TIME 100

int size_of_packet = 0;
int packet_has_sent = 0;
u_int32_t crc32_table[256];
int send_flag = 1; //flag send end,0 is end
u_int8_t dst_mac[6] = {0xA0, 0xE7, 0x0B, 0xAE, 0x45, 0x1B};
u_int8_t src_mac[6] = {0xA0, 0xE7, 0x0B, 0xAE, 0x45, 0x1B};
int filebuffer_count = 0;
int filebuffer_length = 0;

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

std::queue<ethernet_packet> send_queue;
std::mutex tex;

void generate_packet();

void send_packet(pcap_t *adhandle);

void generate_crc32_table();

u_int32_t calculate_crc(u_int8_t *buffer, int len);

void load_ethernet_header(u_int8_t *buffer);

int load_ethernet_data(u_int8_t *buffer, FILE *fp);

int second_load_data(u_int8_t *buffer, u_int8_t *filebuffer);

//generate a packet
void generate_packet() {
    int status = 0;
    //std::string cwd(getcwd(NULL,0));
    //cwd = cwd.substr(0,cwd.rfind('\\'));
    //chdir(cwd.c_str());
    FILE *fp = fopen("..\\test.txt", "rb");
    fseek(fp, 0, SEEK_END);
    filebuffer_length = ftell(fp);
    printf("length: %d\n", filebuffer_length);
    fseek(fp, 0, SEEK_SET);
    u_int8_t *file_buffer = (u_int8_t *) malloc(filebuffer_length * sizeof(u_int8_t));
    fread(file_buffer, sizeof(u_int8_t), filebuffer_length, fp);

    u_int8_t buffer[MAX_SIZE];
    memset(buffer, 0, sizeof(buffer));
    while (send_flag) {
        size_of_packet = 0;
        load_ethernet_header(buffer);
        //status = load_ethernet_data(buffer + sizeof(ethernet_header), fp);
        status = second_load_data(buffer + sizeof(ethernet_header), file_buffer);
        if (status == -1) {
            printf("load data error!\n");
            exit(-1);
        }
        while (send_queue.size() > QUEUE_MAX_SIZE) {
            printf("send queue full!\n");
        }
        tex.lock();
        uint8_t *new_pack = (u_int8_t *) malloc(size_of_packet);
        memcpy(new_pack, buffer, size_of_packet);
        ethernet_packet packet = {new_pack, size_of_packet};
        send_queue.push(packet);
        tex.unlock();
        Sleep(SLEEP_TIME);
    }
    fclose(fp);
}

//send a packet
void send_packet(pcap_t *adhandle) {
    while (send_flag || !send_queue.empty()) {
        while (send_queue.empty()) {
            printf("send queue is empty!\n");
        }
        tex.lock();
        ethernet_packet packet = send_queue.front();
        send_queue.pop();
        int status = pcap_sendpacket(adhandle, (const u_char *) packet.packet, (int) packet.packet_size);
        if (status == 0) {
            printf("%d packets has sent\n", ++packet_has_sent);
        } else {
            printf("send packet %d error! Error code is %d\n", ++packet_has_sent, status);
        }
        free(packet.packet);
        tex.unlock();
        Sleep(SLEEP_TIME);
    }
    pcap_close(adhandle);
}

//generate table
void generate_crc32_table() {
    int i, j;
    u_int32_t crc;
    for (i = 0; i < 256; i++) {
        crc = i;
        for (j = 0; j < 8; j++) {
            if (crc & 1)
                crc = (crc >> 1) ^ 0xEDB88320;
            else
                crc >>= 1;
        }
        crc32_table[i] = crc;
    }
}

u_int32_t calculate_crc(u_int8_t *buffer, int len) {
    int i;
    u_int32_t crc;
    crc = 0xffffffff;
    for (i = 0; i < len; i++) {
        crc = (crc >> 8) ^ crc32_table[(crc & 0xFF) ^ buffer[i]];
    }
    crc ^= 0xffffffff;
    return crc;
}


void load_ethernet_header(u_int8_t *buffer) {
    struct ethernet_header *hdr = (struct ethernet_header *) buffer;
    // add destination and source mac address
    for (int i = 0; i < 6; i++) {
        hdr->dst_mac[i] = dst_mac[i];
        hdr->src_mac[i] = src_mac[i];
    }
    // add source typy
    hdr->ethernet_type = ETHERNET_TYPE;

    // caculate the size of packet now
    size_of_packet += sizeof(ethernet_header);
}

int second_load_data(u_int8_t *buffer, u_int8_t *filebuffer) {
    int size_of_data = 0;
    char tmp[MAX_SIZE];
    memset(tmp, 0, sizeof(tmp));
    while (size_of_data < DATA_MAX_SIZE && filebuffer_count < filebuffer_length) {
        tmp[size_of_data++] = filebuffer[filebuffer_count++];
    }
    if (filebuffer_count >= filebuffer_length) {
        send_flag = 0;
    }
    if (size_of_data < 46 || size_of_data > 1500) {
        printf("Size of data is not satisfied with condition!!!\n");
        printf("\n size of data is : %d\n", size_of_data);
        return -1;
    }
    u_int32_t crc = calculate_crc((u_int8_t *) tmp, size_of_data);
    //printf("%d\n", crc);
    int i;
    for (i = 0; i < size_of_data; i++) {
        *(buffer + i) = tmp[i];
    }
    *(u_int32_t *) (buffer + i) = crc;
    size_of_packet += size_of_data + 4;
    return 1;
}

int load_ethernet_data(u_int8_t *buffer, FILE *fp) {
    int size_of_data = 0;
    char tmp[MAX_SIZE], ch;
    memset(tmp, 0, sizeof(tmp));
    while (size_of_data < DATA_MAX_SIZE && (ch = fgetc(fp)) != EOF) //短路效应可以防止发生错误
    {
        tmp[size_of_data] = ch;
        size_of_data++;
    }
    if (ch == EOF) {
        send_flag = 0;
    }
    if (size_of_data < 46 || size_of_data > 1500) {
        printf("Size of data is not satisfied with condition!!!\n");
        printf("\n size of data is : %d\n", size_of_data);
        return -1;
    }
    //problem: < 46, ADD 0s+1byte;  >1500 LOST

    u_int32_t crc = calculate_crc((u_int8_t *) tmp, size_of_data);
    //printf("%d\n", crc);
    int i;
    for (i = 0; i < size_of_data; i++) {
        *(buffer + i) = tmp[i];
    }
    *(u_int32_t *) (buffer + i) = crc;
    size_of_packet += size_of_data + 4;
    return 1;
}


int main() {
    generate_crc32_table();

    //send the packet
    pcap_t *adhandle;
    pcap_if_t *alldevs;
    pcap_if_t *d;
    int i = 0;
    int inum;
    char error_buffer[PCAP_ERRBUF_SIZE];

    // get the all network adapter handle

    if (pcap_findalldevs(&alldevs, error_buffer) == -1) {
        printf("%s\n", error_buffer);
        return -1;
    }


    /* Print the list of all network adapter information */
    for (d = alldevs; d; d = d->next) {
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" kkk(%s)\n", d->description);
        else
            printf(" (No description available)\n");
    }

    if (i == 0) {
        printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
        return -1;
    }

    printf("Enter the interface number (1-%d):", i);
    scanf("%d", &inum);
    if (inum < 1 || inum > i) {
        printf("\nInterface number out of range.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    /* Jump to the selected adapter */
    for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);



    /* Open the adapter */
    if ((adhandle = pcap_open_live(d->name, // name of the device
                                   65536, // portion of the packet to capture.65536 grants that the whole packet will be captured on/// all the MACs.
                                   1, // promiscuous mode
                                   1000, // read timeout
                                   error_buffer // error buffer
    )) == NULL) {
        printf("\nUnable to open the adapter. %s is not supported by WinPcap\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }


    /* Check the link layer. We support only Ethernet for simplicity. */
    if (pcap_datalink(adhandle) != DLT_EN10MB) {
        printf("\nThis program works only on Ethernet networks.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    std::thread generate_thread(generate_packet);
    std::thread send_thread(send_packet, adhandle);

    generate_thread.join();
    send_thread.join();

    return 0;

}

//构造好ip分组后，如何确定目标ip地址
//数据帧处理，放到数据链路层
//所有帧的处理，放到数据链路层
//对ip分组的处理，放到ip
//对arp分组的处理，放到arp那里

