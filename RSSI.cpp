#include <iostream>
#include <pcap.h>
#include <pthread.h>

void getDeviceID(pcap_if_t * node, pcap_if_t *all_dev, char error_buff[]);
void packet_handler(u_char* args, const struct pcap_pkthdr* packet_header, const u_char* packet_data);
void *sniffer();

int main() {

    /* Parameters for device recognition */
    pcap_if_t *alldevs; /* List that holds all network devices */
    pcap_if_t *node;
    pcap_if_t test;
    char *dev_ID; /* Name of device */
    char error_buffer[PCAP_ERRBUF_SIZE]; /* Error buffer */



    /* Parameters for packet capture */
    pcap_t *dev_handler; /* Handler for reading pkt data */
    const u_char *packet; /* Holds bytes of data from pkt */
    struct pcap_pkthdr packet_header; /* Packet struct */
    int packet_count_limit = 0; /* Number of packets to capture 0 = unlimited */
    int timeout_limit = 10000;  /* Timeout delay */

    if( pcap_findalldevs(&alldevs, error_buffer) == 0 ){
        printf("Network Devices Found\n");
        node = alldevs;
        while (node -> next != NULL) {
            printf("Name of device is %s \n", node->name);
            if( (node -> flags & PCAP_IF_WIRELESS) && (node -> flags & PCAP_IF_CONNECTION_STATUS_DISCONNECTED)){
                dev_ID = node->name;
                break;
            }
            node = node -> next;
        }
    }else{  /* Device not found */
        printf("Error finding device %s\n",error_buffer);
        exit(1);
    }
    //dev_handler = pcap_create(dev_ID,error_buffer);
    //ACTIVATE


//     /* Get the wireless device */
//     getDeviceID(node, all_dev, error_buffer);

//     /* Open dev_ID for receiving packets */
//     dev_handler = pcap_create(dev_ID, error_buffer);
//     pcap_activate(dev_handler);

//     //Need threads one for listening, other for other tasks

//     pthread_t sniff;

//     pthread_create(&sniff,NULL,sniffer,/*args*/);

//     /*
//     Use pcap_loop to constantly listen for packets
//     Once a packet is received, search for the OSI, 
//     if the OSI is APPLE or SAMSUNG or GOOGLE
//         then grab the MAC address and IP address of this packet and store 
//         these value somewhere.
    

//     Using the IP addresses from the list.  Listen to packets
//     if you found a packet with that MAC address
//         get it, seearch for the signal strength value and
//         send this value back to the parent node

//     Do not need to implement socket logic.
    


//     dev_handler = pcap_open_live(
//         dev_ID,
//         BUFSIZ,
//         packet_count_limit,
//         timeout_limit,
//         error_buffer
//     );


//     packet = pcap_next(dev_handler,&packet_header);

//     if(!packet){
//         return 1;
//     }




//     char errbuf[PCAP_ERRBUF_SIZE];
//     pcap_t* handle;

//     // Open the network interface for packet capturing
//     handle = pcap_open_live("your_network_interface", BUFSIZ, 1, 1000, errbuf);
//     if (handle == NULL) {
//         std::cerr << "Couldn't open device: " << errbuf << std::endl;
//         return 1;
//     }

//     // Set a filter to capture only Wi-Fi packets if needed
//     struct bpf_program fp;
//     pcap_compile(handle, &fp, "wlan", 0, PCAP_NETMASK_UNKNOWN);
//     pcap_setfilter(handle, &fp);

//     // Start capturing packets and call packet_handler for each packet
//     pcap_loop(handle, 0, packet_handler, NULL);

//     // Close the packet capture handle
//     pcap_close(handle);
// */
    return 0;
}

void getDeviceID(pcap_if_t * node, pcap_if_t *all_dev, char error_buff[]){
    bool status;
    status = pcap_findalldevs(&all_dev, error_buff); /* Get list of networn devices */
    if(!status){ /* Device found sucessfully */
        printf("Network Device Found\n");
        node = all_dev;
        while (node -> next != NULL) {
            if( (node -> flags & PCAP_IF_WIRELESS) && (node -> flags & PCAP_IF_CONNECTION_STATUS_DISCONNECTED)){
                break;
            }
            node = node -> next;
        }
    }else{  /* Device not found */
        printf("Error finding device %s\n",error_buff);
        exit(1);
    }
}

void packet_handler(u_char* args, const struct pcap_pkthdr* packet_header, const u_char* packet_data){

    //static_cast<int>(packet_data[22])
    //Print signal strength here
    printf(" ");
}