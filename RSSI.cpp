#include <iostream>
#include <pcap.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <string>

void getDeviceID(pcap_if_t **all_devs, pcap_if_t **node_curr, char error_buff[], char **devID, bool debug);
void my_callback(u_char *user,const struct pcap_pkthdr* header,const u_char* bytes);
void *comms(void *args);
/* Struct for packet capture */
struct sniffer{
    pcap_t *dev_handler;    /* Handler for reading pkt data */
    struct pcap_pkthdr * packet_header; /* Packet struct */
    const u_char *packet; /* Holds bytes of data from pkt */
}sniffArgs;

/* Parameters for device recognition */
struct deviceInfo{
    pcap_if_t *alldevs; /* List that holds all network devices */
    pcap_if_t *node;    /* Node used for sniffing */
    char *dev_ID;       /* Name of device */
    char error_buffer[PCAP_ERRBUF_SIZE]; /* Error buffer */
}devRecog;


// Define a structure for the radiotap header
struct ieee80211_radiotap_header {
    u_int8_t it_version;     // set to 0
    u_int8_t it_pad;
    u_int16_t it_len;        // entire length
    u_int32_t it_present;    // fields present
    // Note: actual radiotap data follows
};



/* Main Function */
int main()
{
    /* Get wireless devices info */
    getDeviceID(&devRecog.alldevs, &devRecog.node, devRecog.error_buffer, &devRecog.dev_ID, true);

    /* Create the handler to begin setup */
    if ((sniffArgs.dev_handler = pcap_create(devRecog.dev_ID, devRecog.error_buffer)) == NULL)
    {
        printf("Error creating handler %s\n", devRecog.error_buffer);
        exit(1);
    }

    /* Set the default values for the handler */
    pcap_set_snaplen(sniffArgs.dev_handler, 2048); /* Snapshot length */
    if(pcap_can_set_rfmon(sniffArgs.dev_handler)){
        pcap_set_rfmon(sniffArgs.dev_handler,1);  /* Monitor Mode */
    }
    pcap_set_timeout(sniffArgs.dev_handler,512); /* 512ms timeout */

    /* Activate the handler to begin looping */
    int err = pcap_activate(sniffArgs.dev_handler);
    if( err == 0){
        printf("Device handler activated sucessfully!\n");
    }else if (err > 0){
        pcap_perror(sniffArgs.dev_handler,"Device handler activated with warnings!");
    }else{
        pcap_perror(sniffArgs.dev_handler,"Device handler activation failed!");
        pcap_close(sniffArgs.dev_handler);
        exit(1);
    }
    
    /* Threads for socket communication */
    //pthread_t communicator;
    //pthread_create(&communicator,NULL,analyzer, &sniffArgs.packet_header);

    pcap_loop(sniffArgs.dev_handler,30,my_callback,NULL);

    /*
    Once a packet is received, search for the OSI, 
    if the OSI is APPLE or SAMSUNG or GOOGLE
        then grab the MAC address and IP address of this packet and store 
        these value somewhere.
    

        Using the IP addresses from the list.  Listen to packets
        if you found a packet with that MAC address
            get it, seearch for the signal strength value and
            send this value back to the parent node

        Do not need to implement socket logic.

   */
  

    /* Close Packet Handler */
    // pthread_join(communicator, NULL);

    pcap_close(sniffArgs.dev_handler);
    return 0;
}

void getDeviceID(pcap_if_t **all_devs, pcap_if_t **node_curr, char error_buff[], char **devID, bool debug)
{
    bool track = false;
    if (pcap_findalldevs(all_devs, error_buff) == 0){ /* Device found */
        printf("Network Devices Found\n");
        *node_curr = *all_devs;
        while ((*node_curr)->next != NULL){
            if (debug == true)
                printf("Name of device is %s \n", (*node_curr)->name);
            if (((*node_curr)->flags & PCAP_IF_WIRELESS) && ((*node_curr)->flags & PCAP_IF_RUNNING)){
                *devID = (*node_curr)->name;
                printf("Device to be used: %s \n", *devID);
                track = true;
                break;
            }
            *node_curr = (*node_curr)->next;
        }
    }else{ /* Device not found */
        printf("Error finding device %s\n", error_buff);
        exit(1);
    }

    if(!track){
        printf("Could not find network device that satifies requirements.\n");
        exit(1);
    }
}

void my_callback(u_char *user,const struct pcap_pkthdr* header,const u_char* bytes){
    int8_t v = (int8_t)bytes[14];
    printf("RSSI: %d \n",v);
    //printf("OUI: %02x %02x %02x ",bytes[109],bytes[110],bytes[111]);

    uint16_t radiotap_len = bytes[2] + (bytes[3] << 8);
    int mac= radiotap_len + 10;
    
    printf("OUI: %02x %02x %02x ",bytes[mac], bytes[mac + 1], bytes[mac + 2]);

    /* Reread the readiotap and if that can be implemented*/



// struct ieee802_radiotap_header *rt_header;
//     int rt_header_len;

//     rt_header = (struct ieee80211_radiotap_header *) bytes;
//     rt_header_len = rt_header->it_len;

//     printf("Radiotap Header Length: %d\n", rt_header_len);

//     // RSSI is often found after the radiotap header
//     if (rt_header_len < header->len) {
//         u_int8_t rssi = bytes[rt_header_len];
//         printf("RSSI: %d\n", rssi);
//     } else {
//         printf("No RSSI information available\n");
//     }
    printf("\n");
   // printf("Test %s\n",bytes);
  
}   

// one thread for sniffer (send data to node routine)
// one thread hold OSI save devices we want
// one thread reliest on list from other list () from sniffer