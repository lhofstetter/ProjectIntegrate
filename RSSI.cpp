#include <iostream>
#include <pcap.h>
#include <pthread.h>

void getDeviceID(pcap_if_t **all_devs, pcap_if_t **node_curr, char error_buff[], char **devID, bool debug);
// void packet_handler(u_char* args, const struct pcap_pkthdr* packet_header, const u_char* packet_data);
void *sniffer(void *args);
void *analyzer(void *args);

int main()
{

    /* Parameters for device recognition */
    pcap_if_t *alldevs; /* List that holds all network devices */
    pcap_if_t *node;    /* Node used for sniffing */
    char *dev_ID;       /* Name of device */

    /* Parameters for packet capture */
    pcap_t *dev_handler; /* Handler for reading pkt data */
    // const u_char *packet; /* Holds bytes of data from pkt */
    struct pcap_pkthdr packet_header; /* Packet struct */

    char error_buffer[PCAP_ERRBUF_SIZE]; /* Error buffer */

    getDeviceID(&alldevs, &node, error_buffer, &dev_ID, false);

    if ((dev_handler = pcap_create(dev_ID, error_buffer)) == NULL)
    {
        printf("Error creating handler %s\n", error_buffer);
        exit(1);
    }

    pcap_set_snaplen(dev_handler, 2048); /* Snapshot length */
    pcap_set_rfmon(dev_handler, 1);      /* Monitor Mode */
    pcap_set_timeout(dev_handler, 512);  /* 512ms timeout */

    int err = pcap_activate(dev_handler);
    if (err == 0)
    {
        printf("Device handler activated sucessfully!\n");
    }
    else if (err > 0)
    {
        printf("Device handler activated with warnings!\n");
    }
    else
    {
        printf("Device handler activation failed!\n");
        pcap_close(dev_handler);
        exit(1);
    }

    /* Threads for running the sniffer and main */
    pthread_t packet_consumer;
    pthread_t packet_producer;

    pthread_create(&packet_producer, NULL, sniffer, (void *)dev_handler, packet_header);
    pthread_create(&packet_consumer, NULL, analyzer, packet_header);

    while (1)
    {
    }
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

    // */
    /* Close Packet Handler */
    pthread_join(packet_consumer, NULL);
    pthread_join(packet_producer, NULL);

    pcap_close(dev_handler);
    return 0;
}

void getDeviceID(pcap_if_t **all_devs, pcap_if_t **node_curr, char error_buff[], char **devID, bool debug)
{
    if (pcap_findalldevs(all_devs, error_buff) == 0)
    {
        printf("Network Devices Found\n");
        *node_curr = *all_devs;
        while ((*node_curr)->next != NULL)
        {
            if (debug == true)
                printf("Name of device is %s \n", (*node_curr)->name);
            if (((*node_curr)->flags & PCAP_IF_WIRELESS) && ((*node_curr)->flags & PCAP_IF_CONNECTION_STATUS_DISCONNECTED))
            {
                *devID = (*node_curr)->name;
                break;
            }
            *node_curr = (*node_curr)->next;
        }
    }
    else
    { /* Device not found */
        printf("Error finding device %s\n", error_buff);
        exit(1);
    }
}

void *sniffer(void *args)
{
    // pcap_t **handler, pcap_pkthdr **phead
    //    pcap_loop(*handler,);
}

void *analyzer(void *args)
{
}

// void packet_handler(u_char* args, const struct pcap_pkthdr* packet_header, const u_char* packet_data){

//     //static_cast<int>(packet_data[22])
//     //Print signal strength here
//     printf(" ");
// }

// one thread for sniffer (send data to node routine)
// one thread hold OSI save devices we want
// one thread reliest on list from other list () from sniffer
// pacap loop call