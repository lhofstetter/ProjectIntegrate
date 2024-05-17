#include <iostream>
#include <pcap.h>
//Compile flags -lpcap test

void getDeviceID(char *dev_ID, char error_buff[]);
void packet_handler(u_char* args, const struct pcap_pkthdr* packet_header, const u_char* packet_data);

int main() {

    /* Parameters for device recognition */
    char *dev_ID; /* Name of device */
    char error_buffer[PCAP_ERRBUF_SIZE]; /* Error buffer */

    /* Parameters for packet capture */
    pcap_t *dev_handler; /* Handler for reading pkt data */
    const u_char *packet; /* Holds bytes of data from pkt */
    struct pcap_pkthdr packet_header; /* Packet struct */
    int packet_count_limit = 0; /* Number of packets to capture 0 = unlimited */
    int timeout_limit = 10000;  /* Timeout delay */

    /* Get the wireless device */
    getDeviceID(dev_ID,error_buffer);

    /* Open dev_ID for receiving packets */
    dev_handler = pcap_open_live(
        dev_ID,
        BUFSIZ,
        packet_count_limit,
        timeout_limit,
        error_buffer
    );


    packet = pcap_next(dev_handler,&packet_header);

    if(!packet){
        return 1;
    }




    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle;

    // Open the network interface for packet capturing
    handle = pcap_open_live("your_network_interface", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        std::cerr << "Couldn't open device: " << errbuf << std::endl;
        return 1;
    }

    // Set a filter to capture only Wi-Fi packets if needed
    struct bpf_program fp;
    pcap_compile(handle, &fp, "wlan", 0, PCAP_NETMASK_UNKNOWN);
    pcap_setfilter(handle, &fp);

    // Start capturing packets and call packet_handler for each packet
    pcap_loop(handle, 0, packet_handler, NULL);

    // Close the packet capture handle
    pcap_close(handle);

    return 0;
}

void getDeviceID(char *dev_ID, char error_buff[]){
    dev_ID = pcap_lookupdev(error_buff);    /* Grab device ID */
    if(dev_ID){ /* Device found sucessfully */
        printf("Network Device Found\n");
    }else{  /* Device not found */
        printf("Error finding device %s\n",error_buff);
    }
}

void packet_handler(u_char* args, const struct pcap_pkthdr* packet_header, const u_char* packet_data){

    //static_cast<int>(packet_data[22])
    //Print signal strength here
    printf("");
}