#ifndef NODE_DEFINITIONS_H
#define NODE_DEFINITIONS_H

#include <sstream>
#include <iostream>
#include <fstream>
#include <string>
#include <map>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/socket.h>
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
#include <regex>
#include <map>
#include <pthread.h>
//#include <cpr/cpr.h>
#include <sys/resource.h>
#include <sys/select.h>

#define PAIRING_PORT 8082
#define DEFAULT_WAIT 10.0
#define DEFAULT_INTERFACE "eth0"

#define WARN 1
#define ERROR 2

namespace LML
{
    std::string createPacket(const std::map<std::string, std::string> &data);
    std::map<std::string, std::string> parsePacket(const std::string &packet);
    int handlePacket(const std::map<std::string, std::string> &packet);
}

void send_udp_packet(const std::string &message, const std::string &ip, int port);
void send_tcp_packet(const std::string &message, const std::string &ip, int port);
std::string exec(const char *cmd);
int get_noise_level(const std::string &interface);
void *root_node(void *arg);
void *leaf_node(void *arg);
void govee_api(const std::string &api_key, const std::string &device_id, const std::string &action, const std::string &value);
void comms(const std::string &message, const std::string &ip, int port, int noise_level);

#endif
