#include <iostream>
#include <pcap.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <string.h>

void getDeviceID(pcap_if_t **all_devs, pcap_if_t **node_curr, char error_buff[], char **devID, bool debug);
void my_callback(u_char *user,const struct pcap_pkthdr* header,const u_char* bytes);

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
    
    pcap_loop(sniffArgs.dev_handler,30,my_callback,NULL);

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
    int8_t rssi = (int8_t)bytes[14];
    printf("RSSI: %d \n",rssi);

    /* Get length of Radiotap header */
    uint16_t radiotap_len = bytes[2] + (bytes[3] << 8);

    /* Mac address is typically 10 byte offset from Radiotap header*/
    int mac= radiotap_len + 10;
    //std::string oui = bytes[mac] + bytes[mac+1 ] + bytes[mac];

    char oui[18];
    sprintf(oui,"%02x:%02x:%02x:%02x:%02x:%02x", bytes[mac], bytes[mac + 1], bytes[mac + 2],bytes[mac+3], bytes[mac + 4], bytes[mac + 5]);
    printf("OUI 222: %s\n",oui);
 
   /*
    if(oui does not exist in the database){
            send the mac address to https://www.macvendorlookup.com/api/v2/{MAC_Address}
            (this will return a json string of the OUI vendor) 
            if the OUI is a mobile device
                add the oui vendor type and mac address to a buffer and monitor the device.
                if devices rssi has changed in x amount of time
                    add it to the whitelist table of devices
                else
                    add it to the blacklist table of devices
            else
                add it to the blacklist table of devices
    }else{
        if whitelisted
            using the rssi perform the distance calculations
            send the distance calc to the main pi
    }
   
    *This logic may not work with apples private addresses

   */
}   