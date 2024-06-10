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
#include <curl/curl.h>
#include <sys/resource.h>
#include <sys/select.h>

#define PAIRING_PORT 8082
#define DEFAULT_WAIT 10.0
#define DEFAULT_INTERFACE "eth0"
#define DEFAULT_CALIBRATION_NUMBER 100

#define DEFAULT_WIRELESS "wlan0"
#define FALLBACK_ANTENNA_INTERFACE "wlan1"

#define WARN 1
#define ERROR 2

#define MAX_LEAVES 3
#define DEFAULT_INTERVAL 50

#define GOVEE_API_URL "https://developer-api.govee.com/v1/devices/control"
#define GOVEE_API_KEY "api_key_here"

#define SMS_API_URL "https://api.twilio.com/2010-04-01/Accounts/ACCOUNT_SID/Messages.json"
#define SMS_API_KEY "twilio_auth_token"
#define SMS_PHONE_NUMBER "+1234567890"         // Twilio phone number
#define DESTINATION_PHONE_NUMBER "+1234567890" // Recipient's number
#define TWILIO_ACCOUNT_SID "ACCOUNT_SID"       // Twilio Account SID

typedef char MAC[48];

namespace LML
{
    std::string createPacket(const std::map<std::string, std::string> &data);
    std::map<std::string, std::string> parsePacket(const std::string &packet);
    int handlePacket(const std::map<std::string, std::string> &packet);
}
void getDeviceID(pcap_if_t **all_devs, pcap_if_t **node_curr, char error_buff[], char **devID, bool debug);
void my_callback(u_char *unused, const struct pcap_pkthdr *header, const u_char *bytes);
void *rssi_thread(void *args);
void send_udp_packet(const std::string &message, const std::string &ip, int port);
void send_tcp_packet(const std::string &message, const std::string &ip, int port);
std::string exec(const char *cmd);
int get_noise_level(const std::string &interface);
void *root_node(void *arg);
void *leaf_node(void *arg);
void govee_api(const std::string &api_key, const std::string &device_id, const std::string &action, const std::string &value);
void comms(const std::string &message, const std::string &ip, int port, int noise_level);

#endif
