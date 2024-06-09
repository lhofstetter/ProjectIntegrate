#include <iostream>
#include <pcap.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <string.h>
#include <math.h>

void getDeviceID(pcap_if_t **all_devs, pcap_if_t **node_curr, char error_buff[], char **devID, bool debug);
void my_callback(u_char *user,const struct pcap_pkthdr* header,const u_char* bytes);
void *sniff(void *args);

// /* Struct for packet capture */
// struct sniffer{
//     pcap_t *dev_handler;    /* Handler for reading pkt data */
//     struct pcap_pkthdr * packet_header; /* Packet struct */
//     const u_char *packet; /* Holds bytes of data from pkt */
// }sniffArgs;

// /* Parameters for device recognition */
// struct deviceInfo{
//     pcap_if_t *alldevs; /* List that holds all network devices */
//     pcap_if_t *node;    /* Node used for sniffing */
//     char *dev_ID;       /* Name of device */
//     char error_buffer[PCAP_ERRBUF_SIZE]; /* Error buffer */
// }devRecog;

struct sniff_input{
    /* Sniffer specific args */
    pcap_t *dev_handler;    /* Handler for reading pkt data */
    struct pcap_pkthdr *packet_header; /* Packet struct */
    const u_char *packet; /* Holds bytes of data from pkt */

    /* Device info specific args */
    pcap_if_t *alldevs; /* List that holds all network devices */
    pcap_if_t *node;    /* Node used for sniffing */
    char *dev_ID;       /* Name of device */
    char error_buffer[PCAP_ERRBUF_SIZE]; /* Error buffer */
}sniffinput;

struct capture{
    char mac_addr[18];
    int8_t rssi;
    char oui[9];
    double distance;
}capture;

/* Main Function */
int main(){

pthread_t test;

pthread_create(&test,NULL,sniff,&sniffinput);

pthread_join(test,NULL);
}

/* Order for arguments: <struct deviceInfo, struct sniffer>*/
void *sniff(void *args){
    struct sniff_input* input = (struct sniff_input*)args;

    /* Get wireless devices info */
    getDeviceID(&input->alldevs, &input->node, input->error_buffer, &input->dev_ID, true);
    
    /* Create the handler to begin setup */
    if ((input->dev_handler = pcap_create(input->dev_ID, input->error_buffer)) == NULL)
    {
        printf("Error creating handler %s\n", input->error_buffer);
        exit(1);
    }

    /* Set the default values for the handler */
    pcap_set_snaplen(input->dev_handler, 2048); /* Snapshot length */
    if(pcap_can_set_rfmon(input->dev_handler)){
        pcap_set_rfmon(input->dev_handler,1);  /* Monitor Mode */
    }
    pcap_set_timeout(input->dev_handler,512); /* 512ms timeout */

    /* Activate the handler to begin looping */
    int err = pcap_activate(input->dev_handler);
    if( err == 0){
        printf("Device handler activated sucessfully!\n");
    }else if (err > 0){
        pcap_perror(input->dev_handler,"Device handler activated with warnings!");
    }else{
        pcap_perror(input->dev_handler,"Device handler activation failed!");
        pcap_close(input->dev_handler);
        exit(1);
    }
    
    pcap_loop(input->dev_handler,50,my_callback,NULL);

    pcap_close(input->dev_handler);
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
    
    /* Get length of entire packet */
    bpf_u_int32 packet_length = header->caplen;

    /* Get length of Radiotap header */
    uint16_t radiotap_len = bytes[2] + (bytes[3] << 8);
    
    /* RSSI is the last element in Radiotap Header*/
    capture.rssi = (int8_t)bytes[radiotap_len-1];
    printf("\n---------------------------------------\n");
    printf("RSSI: %d \n",capture.rssi);

    /* Mac address is typically 10 byte offset from Radiotap header*/
    int src_mac = radiotap_len + 10;

   // char mac_addr[18];
    sprintf(capture.mac_addr,"%02x:%02x:%02x:%02x:%02x:%02x", bytes[src_mac], bytes[src_mac + 1], bytes[src_mac + 2],bytes[src_mac+3], bytes[src_mac + 4], bytes[src_mac + 5]);
    printf("MAC: %s\n",capture.mac_addr);
    int management = radiotap_len + 24;
    int temp = management;
    while(temp >= packet_length){
        if(bytes[temp]==221){
            sprintf(capture.oui,"%02x:%02x:%02x",bytes[temp+2],bytes[temp+3],bytes[temp+4]);
            std::cout<< "Vendor OUI: "<< capture.oui<<std::endl;
            temp = 0;
            break;
        }
        temp++;
    }
    if(temp >= packet_length){
        printf("Vendor ID not found\n");
    }
    double static_rssi_1m = -49;
    capture.distance = pow(10,((static_rssi_1m - capture.rssi)/(10*2.5))); /* 2 < N < 4*/
    printf("Distance: %f\n",capture.distance);

    printf("\n---------------------------------------\n");
    
 /*
Node must ger RSSI from the child node and every other node to calc distances (for triangulation)
if statement to check the condition if indormation was received from each node


 Hash map to store the candidates
 */
//Shared memory buffer


   /*
    if(oui does not exist in the database){
            send the mac address to https://www.macvendorlookup.com/api/v2/{MAC_Address}
            try ti sniff the oui type here to avoid api calls
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

    write data to shared memory buffer
    figure out buffer between socket and sniffer
    reverse ARP for IPv6 
    store everything in a struct.
   

   */
}   