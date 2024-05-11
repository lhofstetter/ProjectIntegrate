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

// Constant Definitions
#include "NodeDefinitions.h"
#include <unistd.h>

using namespace std;


int main() {
    cout << "--------------------- Project Integrate Booting ---------------------" << endl;
    fstream logfile;
    chrono::system_clock::time_point begin = chrono::system_clock::now(); // get timestamp for logging log message times.

    char node_message[200];
    memset(node_message, '\0', sizeof(node_message));

    try {
        logfile.open("log.txt", std::ios_base::out);
        logfile << "[ " << (chrono::system_clock::now() - begin).count() << " ] Log opened successfully." << endl;
    } catch (ifstream::failure e) {
        cout << "[ " << (chrono::system_clock::now() - begin).count() << " ] No log file. Creating..." << endl;
        ofstream file("log.txt");

        file.close();
        logfile.open("log.txt", std::ios_base::out);
        cout << "[ " << (chrono::system_clock::now() - begin).count() << " ] log.txt created. " << endl;
    }

    sockaddr_in6 address, client_address;
    unsigned int client_struct_size = sizeof(client_address);

    logfile << "[ " << (chrono::system_clock::now() - begin).count() << " ] Opening socket for pairing process... " << endl;

    int sockfd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (sockfd < 0) {
        logfile << "[ " << (chrono::system_clock::now() - begin).count() << " ] Socket creation failed. Exiting." << endl;
        exit(EXIT_FAILURE);
    }

    logfile << "[ " << (chrono::system_clock::now() - begin).count() << " ] Socket created successfully. Binding to open port..." << endl;

    address.sin6_family = AF_INET6;
    address.sin6_addr = in6addr_any;
    address.sin6_port = htons(PAIRING_PORT);

    if (bind(sockfd, (struct sockaddr *) &address, sizeof(address)) < 0) {
        logfile << "[ " << (chrono::system_clock::now() - begin).count() << " ] Binding to open port failed. Exiting." << endl;
        exit(EXIT_FAILURE);
    }
    chrono::system_clock::time_point begin_wait = chrono::system_clock::now();

    logfile << "[ " << (begin_wait - begin).count() << " ] Bind successful. Listening for other nodes..." << endl;

    while ((chrono::system_clock::now() - begin_wait).count() < 10.0) { // waiting for other nodes to pair
        if (recvfrom(sockfd, node_message, sizeof(node_message), 0, (struct sockaddr *)&client_address, &client_struct_size) >= 0) {
                logfile << "[ " << (begin_wait - begin).count() << " ] Node detected. Beginning pairing process..." << endl;
        }
    }

    logfile.close();
    close(sockfd);




    return 0;
}