#include <iostream>
#include <pcap.h>
//Compile flags -lpcap

void packet_handler(u_char* user, const struct pcap_pkthdr* pkt_header, const u_char* packet_data) {
    // Parse the packet data here to extract the signal strength value
    // For example, for Wi-Fi packets, parse the IEEE 802.11 header to access the signal strength

    // Print the signal strength value
    std::cout << "Signal Strength: " << static_cast<int>(packet_data[22]) << std::endl;
}

int main() {
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
