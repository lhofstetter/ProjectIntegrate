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
        logfile << "[ " << (epoch_double(&alttv) - begin) << " ] Log opened successfully." << endl;
    } catch (ifstream::failure e) {
        cout << "[ " << (epoch_double(&alttv) - begin) << " ] No log file. Creating..." << endl;
        ofstream file("log.txt");

        file.close();
        logfile.open("log.txt", std::ios_base::out);
        cout << "[ " << (epoch_double(&alttv) - begin) << " ] log.txt created. " << endl;
    }

    sockaddr_in6 address, client_address;
    unsigned int client_struct_size = sizeof(client_address);

    logfile << "[ " << (epoch_double(&alttv) - begin) << " ] Opening socket for pairing process... " << endl;

    int sockfd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    fcntl(sockfd, F_SETFL, O_NONBLOCK);

    if (sockfd < 0) {
        logfile << "[ " << (epoch_double(&alttv) - begin) << " ] Socket creation failed. Exiting." << endl;
        exit(EXIT_FAILURE);
    }

    logfile << "[ " << (epoch_double(&alttv) - begin) << " ] Socket created successfully. Binding to open port..." << endl;

    address.sin6_family = AF_INET6;
    address.sin6_addr = in6addr_any;
    address.sin6_port = htons(PAIRING_PORT);

    if (bind(sockfd, (struct sockaddr *) &address, sizeof(address)) < 0) {
        logfile << "[ " << (epoch_double(&alttv) - begin) << " ] Binding to open port failed. Exiting." << endl;
        exit(EXIT_FAILURE);
    }

    struct timespec connection_wait;
    double connection_wait_begin = epoch_double(&connection_wait);
    

    logfile << "[ " << (epoch_double(&alttv) - begin) << " ] Bind successful. Listening for other nodes..." << endl;

    while ((epoch_double(&alttv) - connection_wait_begin) < 10.0) { // waiting for other nodes to pair
        if (recvfrom(sockfd, node_message, sizeof(node_message), 0, (struct sockaddr *)&client_address, &client_struct_size) >= 0) {
                logfile << "[ " << (epoch_double(&alttv) - begin) << " ] Node detected. Beginning pairing process..." << endl;
        }
    }

    logfile.close();
    close(sockfd);




    return 0;
}