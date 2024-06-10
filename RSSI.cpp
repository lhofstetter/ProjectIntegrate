#include <iostream>
#include <pcap.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <string.h>
#include <math.h>

void getDeviceID(pcap_if_t **all_devs, pcap_if_t **node_curr, char error_buff[], char **devID, bool debug);
void my_callback(u_char *unused, const struct pcap_pkthdr *header, const u_char *bytes);
void *sniff(void *args);

struct sniff_input
{
    pcap_t *dev_handler;
    pcap_if_t *alldevs;
    pcap_if_t *node;
    char *dev_ID;
    char error_buffer[PCAP_ERRBUF_SIZE];
} sniffinput;

struct capture
{
    char mac_addr[18];
    int8_t rssi;
    char oui[9];
    double distance;
} capture;

int main()
{
    pthread_t test;
    pthread_create(&test, NULL, sniff, &sniffinput);
    pthread_join(test, NULL);
}

void *sniff(void *args)
{
    struct sniff_input *input = (struct sniff_input *)args;

    getDeviceID(&input->alldevs, &input->node, input->error_buffer, &input->dev_ID, true);

    input->dev_handler = pcap_create(input->dev_ID, input->error_buffer);
    if (input->dev_handler == NULL)
    {
        printf("Error creating handler: %s\n", input->error_buffer);
        exit(1);
    }

    pcap_set_snaplen(input->dev_handler, 2048);
    if (pcap_can_set_rfmon(input->dev_handler))
    {
        pcap_set_rfmon(input->dev_handler, 1);
    }
    pcap_set_timeout(input->dev_handler, 512);

    if (pcap_activate(input->dev_handler) != 0)
    {
        pcap_perror(input->dev_handler, "Handler activation error:");
        pcap_close(input->dev_handler);
        exit(1);
    }

    pcap_loop(input->dev_handler, 50, my_callback, NULL);
    pcap_close(input->dev_handler);
    return 0;
}

void getDeviceID(pcap_if_t **all_devs, pcap_if_t **node_curr, char error_buff[], char **devID, bool debug)
{
    if (pcap_findalldevs(all_devs, error_buff) != 0)
    {
        printf("Error finding device: %s\n", error_buff);
        exit(1);
    }

    for (*node_curr = *all_devs; *node_curr; *node_curr = (*node_curr)->next)
    {
        if (debug)
        {
            printf("Device: %s\n", (*node_curr)->name);
        }
        if (((*node_curr)->flags & PCAP_IF_WIRELESS) && ((*node_curr)->flags & PCAP_IF_RUNNING))
        {
            *devID = (*node_curr)->name;
            printf("Using device: %s\n", *devID);
            return;
        }
    }

    printf("Suitable device not found.\n");
    exit(1);
}

void my_callback(u_char *unused, const struct pcap_pkthdr *header, const u_char *bytes)
{
    (void)unused; // Ignore unused parameter warning

    bpf_u_int32 packet_length = header->caplen;
    uint16_t radiotap_len = bytes[2] + (bytes[3] << 8);

    capture.rssi = (int8_t)bytes[radiotap_len - 1];
    int src_mac = radiotap_len + 10;

    snprintf(capture.mac_addr, sizeof(capture.mac_addr), "%02x:%02x:%02x:%02x:%02x:%02x",
             bytes[src_mac], bytes[src_mac + 1], bytes[src_mac + 2], bytes[src_mac + 3],
             bytes[src_mac + 4], bytes[src_mac + 5]);
    printf("\n---------------------------------------\n");
    printf("RSSI: %d dBm\n", capture.rssi);
    printf("MAC Address: %s\n", capture.mac_addr);

    int temp = radiotap_len + 24;
    if (static_cast<bpf_u_int32>(temp) < packet_length && bytes[temp] == 221)
    {
        snprintf(capture.oui, sizeof(capture.oui), "%02x:%02x:%02x",
                 bytes[temp + 2], bytes[temp + 3], bytes[temp + 4]);
        printf("Vendor OUI: %s\n", capture.oui);
    }
    else
    {
        printf("Vendor ID not found.\n");
    }

    double static_rssi_1m = -49; // RSSI at 1 meter
    capture.distance = pow(10, ((static_rssi_1m - capture.rssi) / (10 * 2.5)));
    printf("Estimated Distance: %.3f meters\n", capture.distance);
    printf("---------------------------------------\n");
}
