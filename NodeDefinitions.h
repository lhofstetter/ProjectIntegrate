#ifndef NODE_DEFINITIONS_H
#define NODE_DEFINITIONS_H

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/socket.h>
#include <iostream>
#include <fstream>
#include <sys/stat.h>
#include <sys/types.h>
#include <chrono>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <fcntl.h>
#include <pcap/pcap.h>
#include <unistd.h>
#include <array>
#include <memory>
#include <string>
#include <regex>
#include <map>
#include <pthread.h>
#include <cpr/cpr.h>

#define PAIRING_PORT 8082
#define DEFAULT_WAIT 10.0
#define DEFAULT_INTERFACE "eth0"

#define WARN 1
#define ERROR 2

void send_udp_packet(const std::string &message, const std::string &ip, int port);
void send_tcp_packet(const std::string &message, const std::string &ip, int port);
std::string exec(const char *cmd);
int get_noise_level(const std::string &interface);
void *parent_node(void *arg);
void *child_node(void *arg);
void govee_api_call();
void handle_communication();
void *child_node(void *arg);

#endif
