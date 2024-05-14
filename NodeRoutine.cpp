// System Libraries 
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <iostream>
#include <fstream>
#include <sys/stat.h>
#include <sys/types.h>
#include <chrono>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <fcntl.h>
#include <pcap/pcap.h>

// Constant Definitions
#include "NodeDefinitions.h"
#include <unistd.h>

using namespace std;

double epoch_double(struct timespec *tv) {
  if (clock_gettime(CLOCK_REALTIME, tv)) {
    cout << "ERROR: clock_gettime function call failed." << endl;
    exit(1);
  }
  char time_str[32];

  snprintf(time_str, 32, "%ld.%.9ld", tv->tv_sec, tv->tv_nsec);

  return atof(time_str);
}

void logmsg(double begin, struct timespec * current_time, fstream * logfile, string msg, bool log_to_console, int status=0) {
    double logtime = epoch_double(current_time);
    string complete_msg = "[ " + to_string(logtime - begin) + " ] ";

    switch (status) {
        case 1:
            complete_msg += "\x1B[33m" + msg + "\033[0m\t\t";
            break;
        case 2:
            complete_msg += "\x1B[31m" + msg + "\033[0m\t\t";
            break;
        default:
            complete_msg += msg;
    }

    *(logfile) << complete_msg << endl;

    if (log_to_console)
        cout << complete_msg << endl;
}

int main() {
    cout << "-------------------------- Project Integrate --------------------------" << endl;
    fstream logfile;
    struct timespec tv;
    struct timespec alttv;
    double begin = epoch_double(&tv); // get timestamp for logging log message times.

    char node_message[200];
    memset(node_message, '\0', sizeof(node_message));

    try {
        logfile.open("log.txt", std::ios_base::out);
        logmsg(begin, &alttv, &logfile, "Log opened successfully.", false);
    } catch (ifstream::failure e) {
        logmsg(begin, &alttv, &logfile, "No log file. Creating...", true);
        ofstream file("log.txt");

        file.close();
        logfile.open("log.txt", std::ios_base::out);
        logmsg(begin, &alttv, &logfile, "log.txt created. ", true);
    }

    sockaddr_in6 address, client_address;
    unsigned int client_struct_size = sizeof(client_address);

    logmsg(begin, &alttv, &logfile, "Opening socket for pairing process... ", false);

    int sockfd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    fcntl(sockfd, F_SETFL, O_NONBLOCK);

    if (sockfd < 0) {
        logmsg(begin, &alttv, &logfile, "Socket creation failed. Exiting. ", false);
        exit(EXIT_FAILURE);
    }

    logmsg(begin, &alttv, &logfile, "Socket created successfully. Binding to open port...", false);

    address.sin6_family = AF_INET6;
    address.sin6_addr = in6addr_any;
    address.sin6_port = htons(PAIRING_PORT);

    if (bind(sockfd, (struct sockaddr *) &address, sizeof(address)) < 0) {
        logmsg(begin, &alttv, &logfile, "Binding to open port failed. Exiting.", false);
        exit(EXIT_FAILURE);
    }

    struct timespec connection_wait;
    double connection_wait_begin = epoch_double(&connection_wait);
    

    logmsg(begin, &alttv, &logfile, "Setup successful. Listening for other nodes...", true);

    while ((epoch_double(&alttv) - connection_wait_begin) < DEFAULT_WAIT) { // waiting for other nodes to pair
        if (recvfrom(sockfd, node_message, sizeof(node_message), 0, (struct sockaddr *)&client_address, &client_struct_size) >= 0) {
            logmsg(begin, &alttv, &logfile, "Node detected. Beginning pairing process...", true);
        }
    }

    if (node_message[8] == '\0') {
        logmsg(begin, &alttv, &logfile, "No node found. Assuming current node is parent.", true);

        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_if_t * devices;

        /* parent code  */
        if (pcap_findalldevs(&devices, errbuf) == PCAP_ERROR) {
            logmsg(begin, &alttv, &logfile, "ERROR: findalldevs call failed. \n Defaulting to " + string(DEFAULT_INTERFACE) + " will result in decreased effectiveness of system, and is currently unsupported. Please reboot the Pi.", true, 2);

            logfile.close();
            close(sockfd);

            exit(1);
        } else {
            pcap_if_t * node = devices;
            while (node -> next != NULL) {
                if ((node -> flags & PCAP_IF_WIRELESS) && (node -> flags & PCAP_IF_CONNECTION_STATUS_DISCONNECTED)) {   // found wireless adapter that is not currently connected to Wi-Fi network
                    break;
                }
                node = node -> next;
            }

            if (node -> next != NULL) { // successfully found wireless adapter
                char * interface = node -> name;
                logmsg(begin, &alttv, &logfile, "Interface using wireless adapter found under " + string(interface) + ".", false);
                pcap_t * device = pcap_create(interface, errbuf);
                pcap_setnonblock(device, 0, errbuf);
                
                if (pcap_can_set_rfmon(device) <= 0) {
                    logmsg(begin, &alttv, &logfile, "ERROR: " + string(interface) + " is incapable of monitor mode. Please double check driver install.", true, 2);
                    pcap_freealldevs(devices);
                    logfile.close();
                    close(sockfd);
                    exit(1);
                } else {
                    if (pcap_set_rfmon(device, 1) != 0) {
                        logmsg(begin, &alttv, &logfile, "ERROR: Failed to set monitor mode on " + string(interface) + ". Please double check driver install or reboot Pi.", true, 2);
                        pcap_freealldevs(devices);
                        logfile.close();
                        close(sockfd);
                        exit(1);
                    }

                    
                }


            } else {
                logmsg(begin, &alttv, &logfile, "ERROR: No alternate wireless adapter found. Using " + string(DEFAULT_INTERFACE) + " will result in decreased effectiveness of system, and is currently unsupported. Please reboot the Pi.", true, 2);

                logfile.close();
                close(sockfd);
                pcap_freealldevs(devices);

                exit(1);
            }
        }


    } else {
        logmsg(begin, &alttv, &logfile, "Node detected.", true);
        /* child code goes here */
    }










    logfile.close();
    close(sockfd);




    return 0;
}