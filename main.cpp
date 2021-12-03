
#include "DataLinkLayer.h"

uint8_t dst_mac[6] = {0xA0, 0xE7, 0x0B, 0xAE, 0x45, 0x1B};
uint8_t src_mac[6] = {0xA0, 0xE7, 0x0B, 0xAE, 0x45, 0x1B};

int main() {

    DataLinkLayer data_link(src_mac, dst_mac);
    data_link.data_loader();

    data_link.run();

    return 0;

}

//构造好ip分组后，如何确定目标ip地址
//数据帧处理，放到数据链路层
//所有帧的处理，放到数据链路层
//对ip分组的处理，放到ip
//对arp分组的处理，放到arp那里

