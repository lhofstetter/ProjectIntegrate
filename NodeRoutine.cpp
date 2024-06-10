#include "NodeDefinitions.h"

using namespace std;

vector<string> deviceIDs = {"device_id_1", "device_id_2", "device_id_3"};
sched_param pr = {sched_get_priority_max(SCHED_RR)};
const sched_param *priority = &pr;
const unsigned char LML_types[] = {0b000, 0b001, 0b010, 0b011, 0b100, 0b101, 0b110, 0b111};
unsigned char noise_level;
unsigned char interval;

const string LML_Types[] = {"type", "noise", "candidate", "signal_data", "device", "action", "configure", "port", "protocol", "name_of_device", "devices", "socket_to_communicate", "type_of_socket_used_for_communication", "interval"};

// Global Structs
struct LeafDetails
{
    int port;
    string ipAddress;
    int identifierNumber;
    int socket;
    int interval;
    map<string, int> distanceFromSiblings;
    string deviceID;
};

map<string, LeafDetails> leaf_details;

struct Args
{
    int socket_fd;
    fstream *log_file;
    double time_begin;
    timespec tv, alt_tv;
    char node_message[200];
    sockaddr_in6 root_ip;
    int16_t interval;
};

// RSSI Thread Structs
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

// Callback function for SMS response
static size_t SMSResponseCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    ((std::string *)userp)->append((char *)contents, size * nmemb);
    return size * nmemb;
}

// Function to send SMS using Twilio API
void sendSMS(const std::string &message, const std::string &recipientNumber)
{
    CURL *curl;
    CURLcode res;
    std::string readBuffer;

    curl = curl_easy_init();
    if (curl)
    {
        char *escapedMessage = curl_easy_escape(curl, message.c_str(), message.length());
        if (escapedMessage)
        {
            std::string postData = "To=" + recipientNumber + "&From=" + SMS_PHONE_NUMBER + "&Body=" + escapedMessage;

            curl_easy_setopt(curl, CURLOPT_USERNAME, TWILIO_ACCOUNT_SID);
            curl_easy_setopt(curl, CURLOPT_PASSWORD, SMS_API_KEY);
            curl_easy_setopt(curl, CURLOPT_URL, SMS_API_URL);
            curl_easy_setopt(curl, CURLOPT_POST, 1L);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postData.c_str());
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, SMSResponseCallback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);

            res = curl_easy_perform(curl);
            if (res != CURLE_OK)
            {
                std::cerr << "curl_easy_perform() failed: " << curl_easy_strerror(res) << std::endl;
            }
            else
            {
                std::cout << "SMS sent successfully: " << readBuffer << std::endl;
            }

            curl_free(escapedMessage);
        }
        curl_easy_cleanup(curl);
    }
}

// START OF ALERT SYSTEM FUNCTION
// To be called by other critical operations to send SMS to owner (optional)
void alertSystem(const std::string &message)
{
    static std::chrono::steady_clock::time_point last_alert_time;
    std::chrono::seconds alert_cooldown(300); // 5 minutes cooldown

    auto now = std::chrono::steady_clock::now();
    if (now - last_alert_time > alert_cooldown)
    {
        last_alert_time = now;
        std::cerr << "Alert: " << message << std::endl;
        sendSMS(message, DESTINATION_PHONE_NUMBER);
    }
    else
    {
        std::cerr << "Alert suppressed (cooldown): " << message << std::endl;
    }
}

void logError(const std::string &message)
{
    std::cerr << "Error: " << message << std::endl;
    std::ofstream logFile("error.log", std::ios::app);
    if (logFile.is_open())
    {
        logFile << "Error: " << message << std::endl;
        logFile.close();
    }
}

void assignDeviceIDs()
{
    int index = 0;
    for (auto &leaf_pair : leaf_details)
    {
        leaf_pair.second.deviceID = deviceIDs[index % deviceIDs.size()];
        index++;
    }
}
/*
void handleLeafRequest(const std::string &leafID, const std::string &action, const std::string &value)
{
    auto it = leaf_details.find(leafID);
    if (it != leaf_details.end())
    {
        govee_api(GOVEE_API_KEY, it->second.deviceID, action, value); // Use the GOVEE_API_KEY macro here
    }
    else
    {
        std::cerr << "Leaf ID not found: " << leafID << std::endl;
    }
}
*/

// LML Functions
namespace LML
{
    std::string createPacket(const std::map<std::string, std::string> &data)
    {
        std::stringstream packet;
        packet << "{";
        for (const auto &kv : data)
        {
            packet << "\"" << kv.first << "\":\"" << kv.second << "\",";
        }
        if (!data.empty())
        {
            packet.seekp(-1, std::ios_base::end);
        }
        packet << "}";
        return packet.str();
    }

    std::map<std::string, std::string> parsePacket(const std::string &packet)
    {
        std::map<std::string, std::string> data;
        std::string key, value;
        bool isKey = true, inQuotes = false;
        for (char c : packet)
        {
            if (c == '{' || c == '}')
                continue;
            if (c == '"')
            {
                inQuotes = !inQuotes;
                continue;
            }
            if (!inQuotes && c == ':')
            {
                isKey = false;
                continue;
            }
            if (!inQuotes && c == ',')
            {
                data[key] = value;
                key = "";
                value = "";
                isKey = true;
                continue;
            }
            if (inQuotes)
            {
                (isKey ? key : value) += c;
            }
        }
        if (!key.empty() && !value.empty())
        {
            data[key] = value;
        }
        return data;
    }

    // NEED TO IMPLEMENT FUNCTIONS
    int handlePacket(const std::map<std::string, std::string> &packet)
    {
        auto it = packet.find("type");
        if (it == packet.end())
        {
            logError("Packet received without a type specified.");
            return -1; // Signal error.
        }
        const std::string &type = it->second;
        if (type == "pairing")
        {
            return 0; // Signal success.
        }
        else if (type == "calibration")
        {
            return 0; // Signal success.
        }
        else if (type == "signal_data")
        {
            return 0; // Signal success.
        }
        else
        {
            logError("Unhandled packet type encountered: " + type);
            alertSystem("Received an unrecognized packet type, which requires manual inspection. Type: " + type);
            return -1; // Signal error.
        }
    }
}

map<string, string> parse_json(char *node_msg)
{
    map<string, string> m;
    size_t i;
    string current_str = "";
    for (i = 0; i < strlen(node_msg); i++)
    {
        current_str += string(1, node_msg[i]);
        if (current_str == "{\n" || current_str == ",\n")
        {
            current_str = "";
        }

        if (current_str.length() >= 4)
        {
            for (size_t y = 0; y < sizeof(LML_Types) / sizeof(LML_Types[0]); y++)
            {
                if (current_str.find(LML_Types[y] + ":") != string::npos)
                {
                    current_str = "";
                    size_t x;

                    for (x = i; node_msg[x] != '\n' && node_msg[x] != '\0'; x++)
                    {
                        current_str += string(1, node_msg[x]);
                    }

                    m[LML_Types[y]] = current_str;
                    i = x;
                }
            }
        }
    }

    return m;
}

double epoch_double(struct timespec *tv)
{
    if (clock_gettime(CLOCK_REALTIME, tv))
    {
        cout << "ERROR: clock_gettime function call failed." << endl;
        exit(1);
    }
    char time_str[32];

    snprintf(time_str, 32, "%ld.%.9ld", tv->tv_sec, tv->tv_nsec);

    return atof(time_str);
}

void logmsg(double begin, struct timespec *current_time, fstream *logfile, string msg, bool log_to_console, int status = 0)
{
    double logtime = epoch_double(current_time);
    string complete_msg = "[ " + to_string(logtime - begin) + " ] ";

    switch (status)
    {
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

std::string noise(const char *cmd)
{
    std::array<char, 128> buffer;
    std::string result;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
    if (!pipe)
    {
        throw std::runtime_error("popen() failed!");
    }
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr)
    {
        result += buffer.data();
    }
    return result;
}

// Get Noise level from NIC
int get_noise_level(const std::string &interface)
{
    std::string command = "iwconfig " + interface;
    std::string output = noise(command.c_str());

    std::regex noise_regex("(Noise level=(-?\\d+))");
    std::smatch match;
    int noise_level = -1;

    if (std::regex_search(output, match, noise_regex) && match.size() > 1)
    {
        noise_level = std::stoi(match.str(1));
    }

    return noise_level;
}

// OPTIONAL: Shortcut function to determine best protocol if needed
void comms(const string &message, const string &ip, int port, int noise_level)
{
    if (noise_level < -80)
    {
        cout << "Low noise level detected. Using UDP for communication." << endl;
        send_udp_packet(message, ip, port);
    }
    else
    {
        cout << "High noise level detected. Using TCP for communication." << endl;
        send_tcp_packet(message, ip, port);
    }
}

// Prepare UDP packet
void send_udp_packet(const std::string &message, const std::string &ip, int port)
{
    int sockfd = socket(AF_INET6, SOCK_DGRAM, 0);
    if (sockfd < 0)
    {
        perror("socket");
        return;
    }

    struct sockaddr_in6 server_addr
    {
    };
    server_addr.sin6_family = AF_INET6;
    inet_pton(AF_INET6, ip.c_str(), &server_addr.sin6_addr);
    server_addr.sin6_port = htons(port);

    sendto(sockfd, message.c_str(), message.size(), 0, (struct sockaddr *)&server_addr, sizeof(server_addr));
    close(sockfd);
}

// Prepare TCP packet
void send_tcp_packet(const std::string &message, const std::string &ip, int port)
{
    int sockfd = socket(AF_INET6, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        perror("socket");
        return;
    }

    struct sockaddr_in6 server_addr
    {
    };
    server_addr.sin6_family = AF_INET6;
    inet_pton(AF_INET6, ip.c_str(), &server_addr.sin6_addr);
    server_addr.sin6_port = htons(port);

    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("connect");
        close(sockfd);
        return;
    }

    send(sockfd, message.c_str(), message.size(), 0);
    close(sockfd);
}

// Callback for govee_api
static size_t GoveeCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    ((std::string *)userp)->append((char *)contents, size * nmemb);
    return size * nmemb;
}

// Function to send API requests to Govee
/*
void govee_api(const string &device_id, const string &action, const string &value)
{
    CURL *curl;
    CURLcode res;
    std::string readBuffer;
    std::string postData = "{\"device\": \"" + device_id + "\", \"model\": \"H6008\", \"cmd\": {\"name\": \"" + action + "\", \"value\": \"" + value + "\"}}";

    curl = curl_easy_init();
    if (curl)
    {
        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        std::string authHeader = "Govee-API-Key: " + std::string(GOVEE_API_KEY);
        headers = curl_slist_append(headers, authHeader.c_str());

        curl_easy_setopt(curl, CURLOPT_URL, GOVEE_API_URL);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postData.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, GoveeCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);

        res = curl_easy_perform(curl);
        if (res != CURLE_OK)
        {
            std::string error_message = "Govee API call failed: " + std::string(curl_easy_strerror(res));
            std::cerr << error_message << std::endl;
            // alertSystem(error_message); // Trigger alert system on failure
        }
        else
        {
            std::cout << "HTTP Response:\n"
                      << readBuffer << std::endl;
        }

        curl_easy_cleanup(curl);
        curl_slist_free_all(headers);
    }
    else
    {
        alertSystem("Failed to initialize CURL for Govee API call.");
    }
}
*/

// RSSI void functions and thread
void getDeviceID(pcap_if_t **all_devs, pcap_if_t **node_curr, char error_buff[], char **devID, bool debug)
{
    if (pcap_findalldevs(all_devs, error_buff) != 0)
    {
        logError("Error finding device: " + std::string(error_buff));
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

    logError("Suitable device not found.");
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

void *rssi_thread_func(void *args)
{
    while (true)
    {
        getDeviceID(&sniffinput.alldevs, &sniffinput.node, sniffinput.error_buffer, &sniffinput.dev_ID, true);

        sniffinput.dev_handler = pcap_create(sniffinput.dev_ID, sniffinput.error_buffer);
        if (sniffinput.dev_handler == NULL)
        {
            logError("Error creating handler: " + std::string(sniffinput.error_buffer));
            continue;
        }

        pcap_set_snaplen(sniffinput.dev_handler, 2048);
        if (pcap_can_set_rfmon(sniffinput.dev_handler))
        {
            pcap_set_rfmon(sniffinput.dev_handler, 1);
        }
        pcap_set_timeout(sniffinput.dev_handler, 512);

        if (pcap_activate(sniffinput.dev_handler) != 0)
        {
            pcap_perror(sniffinput.dev_handler, "Handler activation error:");
            pcap_close(sniffinput.dev_handler);
            continue;
        }

        pcap_loop(sniffinput.dev_handler, 0, my_callback, NULL);
        pcap_close(sniffinput.dev_handler);
    }

    return NULL;
}

// Thread to make sure both NICs are on the same channel
// Function to execute shell commands and get results
std::string exec(const char *cmd)
{
    char buffer[128];
    std::string result = "";
    FILE *pipe = popen(cmd, "r");
    if (!pipe)
        throw std::runtime_error("popen() failed!");
    try
    {
        while (fgets(buffer, sizeof(buffer), pipe) != nullptr)
        {
            result += buffer;
        }
    }
    catch (...)
    {
        pclose(pipe);
        throw;
    }
    pclose(pipe);
    return result;
}

// Thread function for channel synchronization
void *channel_sync_thread(void *arg)
{
    std::string findInterfaceCmd = "iw dev | grep Interface | awk '{print $2}' | grep -v '^" DEFAULT_WIRELESS "$' | head -n 1";
    std::string antennaInterface = exec(findInterfaceCmd.c_str());
    if (antennaInterface.empty())
    {
        antennaInterface = FALLBACK_ANTENNA_INTERFACE; // Use fallback if no other interface found (Trying to make this code portable)
        std::cout << "Fallback interface used: " << antennaInterface << std::endl;
    }

    // Trim possible new line character
    antennaInterface.erase(std::remove(antennaInterface.begin(), antennaInterface.end(), '\n'), antennaInterface.end());

    std::string setupCmd = "ip link set " + antennaInterface + " down && " +
                           "iw dev " + antennaInterface + " set type monitor && " +
                           "ip link set " + antennaInterface + " up";
    system(setupCmd.c_str());

    std::string current_channel;
    while (true)
    {
        std::string channelCmd = "iw dev " DEFAULT_WIRELESS " info | grep channel | awk '{print $2}'";
        std::string new_channel = exec(channelCmd.c_str());
        if (new_channel != current_channel)
        {
            std::string changeChannelCmd = "iw dev " + antennaInterface + " set channel " + new_channel;
            system(changeChannelCmd.c_str());
            current_channel = new_channel;
            std::cout << "Channel updated to " << current_channel << " on " << antennaInterface << std::endl;
        }
        sleep(60); // Check every minute? Longer?
    }
    return NULL;
}

// After pairing, parent needs to listen to children
// @todo: Implement sockets setup for communication with children
// @todo: Implement logic for distance measurements from children
// Triangulation logic to determine relative positions
// Calculate distances between the user and devices
// Decide action based on threshold values
// API calls to control devices based on proximity
// Logic to turn off devices when user exits the threshold area
void *root_node(void *args)
{
    struct Args *arguments = (struct Args *)args;

    if (pthread_setschedparam(pthread_self(), SCHED_RR, priority) == ESRCH)
    {
        logmsg(arguments->time_begin, &(arguments->alt_tv), (arguments->log_file), "Unable to set scheduling policy. Performance of Integrate may suffer. Please try to rerun the program with root permissions.", true, 1);
    }

    map<string, LeafDetails> leaf_details;
    int paired_leaves = 0;

    timespec new_tv, new_alt_tv;
    new_tv = arguments->tv;
    new_alt_tv = arguments->alt_tv;
    logmsg(arguments->time_begin, &new_alt_tv, arguments->log_file, "Root status confirmed. Entering pairing phase.", true);

    int sock = arguments->socket_fd;
    // Broadcast pairing message
    sockaddr_in6 broadcast;
    struct in6_addr broadcast_addr;
    inet_pton(AF_INET6, "ff02::1", &broadcast_addr);
    broadcast.sin6_addr = broadcast_addr;
    broadcast.sin6_family = AF_INET6;
    broadcast.sin6_port = htons(PAIRING_PORT);
    const sockaddr *generic_addr = reinterpret_cast<const sockaddr *>(&broadcast);
    sockaddr_in6 sender_address;
    socklen_t sender_address_len = sizeof(sender_address);
    char *buffer = arguments->node_message;

    while (paired_leaves < MAX_LEAVES)
    {
        memset(buffer, '\0', 200);
        string msg = "{\n\"type\":\"pairing\",\n\"noise\":\"" + to_string(get_noise_level("wlan0")) + "\",\n\"interval\":" + to_string(DEFAULT_INTERVAL + (DEFAULT_INTERVAL * paired_leaves)) + "\n}";
        sendto(sock, msg.c_str(), msg.size(), 0, (const sockaddr *)generic_addr, sizeof(broadcast));
        // recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&sender_address, &sender_address_len);
        // Listening for children responses

        ssize_t message_len = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&sender_address, &sender_address_len);
        if (message_len > 0)
        {
            buffer[message_len] = '\0'; // @attention: @Marley why are we getting rid of the last byte?
            string response(buffer);
            char ipv6Addr[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &(sender_address.sin6_addr), ipv6Addr, INET6_ADDRSTRLEN);
            string ipAddr = ipv6Addr;

            string leaf_identifier = "Leaf#" + to_string(paired_leaves + 1);
            if (leaf_details.find(leaf_identifier) == leaf_details.end())
            {
                LeafDetails details = {PAIRING_PORT, ipAddr, paired_leaves + 1, DEFAULT_INTERVAL + (DEFAULT_INTERVAL * paired_leaves)};
                leaf_details[leaf_identifier] = details;
                logmsg(arguments->time_begin, &new_alt_tv, arguments->log_file, "Paired with new leaf node: " + leaf_identifier + " on port " + to_string(details.port) + " with IP " + details.ipAddress + ".", true);
                paired_leaves++;
            }
        }
        sleep(5);
    }
    assignDeviceIDs();

    logmsg(arguments->time_begin, &new_alt_tv, arguments->log_file, "All leaves paired.", true);

    cout << "All leaves paired. Connection details:" << endl;
    for (const auto &leaf : leaf_details)
    {
        cout << leaf.first << " - IP: " << leaf.second.ipAddress
             << ", Port: " << leaf.second.port
             << ", Identifier: " << leaf.second.identifierNumber << endl;
    }

    // After all leaves are paired, begin calibration process.
    memset(buffer, '\0', 200);
    ssize_t message_length;

    for (int i = 0; i < paired_leaves; i++)
    {
        string msg = "{\n\"type\":\"calibration\",\n\"noise\":\"" + to_string(get_noise_level("wlan0")) + ",\n\"num_of_calibration_packets\":" + to_string(DEFAULT_CALIBRATION_NUMBER) + ",\n\"leaf\":" + leaf_details["Leaf#" + to_string(i + 1)].ipAddress + "\n}";
        sendto(sock, msg.c_str(), msg.size(), 0, (const sockaddr *)generic_addr, sizeof(broadcast));
        sleep(10); // sleep period while waiting for leaf to begin blasting calibration packets
        bool leaves[paired_leaves - 1];
        memset(leaves, false, sizeof(leaves));
        bool cond = true;
        while (cond)
        {
            message_length = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&sender_address, &sender_address_len);
            if (message_length <= 0)
            {
                continue; // no message in the buffer or empty message
            }
            else
            {
                map<string, string> packet = parse_json(buffer);
                if (packet.find("packets_remaining") != packet.end())
                {
                    if (stoi(packet["packets_remaining"]) == 0)
                    {
                        // the child has finished it's burst. We should now check to see if the other leaves received successfully.
                        while ((message_length = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&sender_address, &sender_address_len)) <= 0)
                        {
                            continue; // wait until there's something in the socket
                        }

                        packet = parse_json(buffer);
                        if (packet.find("distance") != packet.end())
                        {
                            for (int x = 0; x < paired_leaves - 1; x++)
                            {
                                unsigned char buf[sizeof(struct in6_addr)];
                                inet_pton(AF_INET6, leaf_details["Leaf#" + to_string(x + 1)].ipAddress.c_str(), buf);
                                if (buf == sender_address.sin6_addr.s6_addr)
                                { // compares the IP address of the stored leaf to the one that just came in. If it matches, store the distance estimate with it's sibling and move on.
                                    leaves[x] = true;
                                    leaf_details["Leaf#" + to_string(x + 1)].distanceFromSiblings.insert({packet["leaf"], stoi(packet["distance"])});
                                    break;
                                }
                            } // horribly inefficient way to do this, but it should work (I think lol).
                            for (int x = 0; x < paired_leaves - 1; x++)
                            {
                                if (leaves[x])
                                {
                                    if (x == paired_leaves - 2)
                                    {
                                        cond = true;
                                    }
                                }
                                else
                                {
                                    break; // if one leaf isn't marked true, then it doesn't matter what the others are because it won't
                                    // change the fact that we still need to be listening for other confirmation number. So keep listening.
                                }
                            }
                        }
                    }
                    else
                    {
                        continue; // this isn't the last packet. Continue and load the next packet.
                    }
                }
                else
                {
                    continue; // we don't know what packet this is, but it's not one we care about. Move on.
                }
            }
        }
    } // handleLeafRequest(leafID, action, value); add this in to handle leaftrequests
      // Potential example??
    /* logmsg(arguments->time_begin, &new_alt_tv, arguments->log_file, "Calibration complete. System operational.", true);
while (true) {
memset(buffer, 0, 200);
ssize_t message_len = recvfrom(sock, buffer, 200, 0, (struct sockaddr *)&sender_address, &sender_address_len);
if (message_len > 0) {
    buffer[message_len] = '\0';
    map<string, string> packet = parse_json(buffer);

    // Check for specific commands or status updates from leaf nodes
    if (packet["type"] == "command" && packet.count("command") && packet.count("leafID")) {
        string leafID = packet["leafID"];
        string command = packet["command"];
        string value = packet.count("value") ? packet["value"] : "";
        handleLeafRequest(leafID, command, value);
    }
}
}
delete[] buffer;
close(sock);
return NULL;
*/

    // calibration phase complete. The root now stores details for every sibling's distance from it's other siblings. We can actually
    // start doing our job now :D

    // generate candidate list. Also, the root's distance from it's leaves has not yet been determined at this phase. That happens once the
    // sniffer thread is running.

    while (true)
    {
        // create sniffer thread and let it begin it's job. From now on we must assume that we are not always in control of the
        // CPU, so keep that in mind.
    }

    close(sock);
    return NULL;
}

void *leaf_node(void *args)
{

    struct Args *arguments = (struct Args *)args;

    if (pthread_setschedparam(pthread_self(), SCHED_FIFO, priority) != 0)
    { // WARNING: successful scheduling policy change means we HAVE to manually yield thread from here on out
        logmsg(arguments->time_begin, &(arguments->alt_tv), (arguments->log_file), "Unable to set scheduling policy. Performance of Integrate may suffer. Please try to rerun the program with root permissions.", true, 1);
    }

    map<string, LeafDetails> leaf_details;
    int paired_leaves = 0;

    timespec new_tv, new_alt_tv;
    new_tv = arguments->tv;
    new_alt_tv = arguments->alt_tv;
    timespec ints_tv;
    logmsg(arguments->time_begin, &new_alt_tv, arguments->log_file, "Leaf status confirmed. Confirming pairing with root.", true);

    int sock = arguments->socket_fd;
    map<string, string> data; // To store assigned identifier and port

    // Send initial pairing requests until an assignment is received
    char *buffer = arguments->node_message;
    sockaddr_in6 root_address = arguments->root_ip;
    socklen_t root_address_len = sizeof(root_address);
    ssize_t message_len;
    string message = "{\n\"type\":\"pairing\",\n\"noise\":\"" + to_string(get_noise_level("wlan0")) + "\",\nconfirmation: true,\n}";

    sendto(sock, message.c_str(), message.size(), 0, (struct sockaddr *)&root_address, sizeof(root_address));
    // confirmation for pairing with the root.

    // need to implement calibration phase here - with a wait until it actually begins.
    while (true)
    {
        message_len = recvfrom(sock, buffer, sizeof(&buffer), 0, (struct sockaddr *)&root_address, &root_address_len);
        if (message_len > 0)
        {
            data = parse_json(buffer);
        }
    }

    /*
        Need to begin sniffer thread here before entering while loop for socket operations.
        That means we need to make the shared memory buffer and everything else that the leaf and sniffer both need to communicate.
    */

    double interval_start = epoch_double(&ints_tv);

    while (true)
    { // this is probably gonna end up as a simple event-driven system - in order to enable it to respond to different messages from root.
        if (epoch_double(&ints_tv) - interval_start < arguments->interval - 0.002)
        { // give the code 20 ms to send data
            message_len = recvfrom(sock, buffer, sizeof(&buffer), 0, (struct sockaddr *)&root_address, &root_address_len);
            if (message_len > 0)
            {
            }
        }
    }

    close(sock);
    return NULL;
}

#ifndef LML_TEST
int main()
{
    cout << "-------------------------- Project Integrate --------------------------" << endl;
    pthread_t root_thread, leaf_thread, rssi_thread, channel_thread;
    if (pthread_create(&rssi_thread, NULL, rssi_thread_func, NULL) != 0)
    {
        perror("Failed to create the RSSI thread");
        return EXIT_FAILURE;
    }
    if (pthread_create(&channel_thread, NULL, channel_sync_thread, NULL) != 0)
    {
        std::cerr << "Failed to create channel synchronization thread" << std::endl;
        return 1;
    }

    Args *args = (struct Args *)malloc(sizeof(struct Args));
    fstream logfile;
    struct timespec tv, alttv;
    double begin = epoch_double(&tv);
    char node_message[200];
    memset(node_message, '\0', sizeof(node_message));

    cout << sizeof(noise_level) << endl;

    try
    {
        logfile.open("log.txt", ios_base::out);
        logmsg(begin, &alttv, &logfile, "Log opened successfully.", false);
    }
    catch (ifstream::failure e)
    {
        logmsg(begin, &alttv, &logfile, "No log file. Creating...", true);
        ofstream file("log.txt");
        file.close();
        logfile.open("log.txt", ios_base::out);
        logmsg(begin, &alttv, &logfile, "log.txt created.", true);
    }

    sockaddr_in6 address, client_address;
    unsigned int client_struct_size = sizeof(client_address);

    logmsg(begin, &alttv, &logfile, "Opening socket for pairing process...", false);

    int sockfd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    fcntl(sockfd, F_SETFL, O_NONBLOCK);

    if (sockfd < 0)
    {
        logmsg(begin, &alttv, &logfile, "Socket creation failed. Exiting.", false);
        exit(EXIT_FAILURE);
    }

    logmsg(begin, &alttv, &logfile, "Socket created successfully. Binding to open port...", false);

    address.sin6_family = AF_INET6;
    address.sin6_addr = in6addr_any;
    address.sin6_port = htons(PAIRING_PORT);

    if (::bind(sockfd, (struct sockaddr *)&address, sizeof(address)) < 0)
    {
        logmsg(begin, &alttv, &logfile, "Binding to open port failed. Exiting.", false);
        exit(EXIT_FAILURE);
    }

    struct timespec connection_wait;
    double connection_wait_begin = epoch_double(&connection_wait);

    logmsg(begin, &alttv, &logfile, "Setup successful. Listening for other nodes...", true);

    sockaddr_in6 broadcast;
    struct in6_addr broadcast_addr;
    inet_pton(AF_INET6, "ff02::1", &broadcast_addr);

    broadcast.sin6_addr = broadcast_addr;
    broadcast.sin6_family = AF_INET6;
    broadcast.sin6_port = htons(PAIRING_PORT);
    char msg[128];

    const sockaddr *generic_addr = reinterpret_cast<const sockaddr *>(&broadcast);

    sendto(sockfd, msg, sizeof(msg), 0, (const sockaddr *)generic_addr, sizeof(broadcast));

    map<string, string> packet;

    bool am_root_node = true;

    while ((epoch_double(&alttv) - connection_wait_begin) < DEFAULT_WAIT)
    {
        if (recvfrom(sockfd, node_message, sizeof(node_message), 0, (struct sockaddr *)&client_address, &client_struct_size) > 0)
        {
            packet = parse_json(node_message);
            if (packet.find("interval") != packet.end())
            {
                am_root_node = false;
                args->root_ip = client_address;
                args->interval = stoi(packet["interval"]);
                break;
            }
        }
        else
        {
            sendto(sockfd, msg, sizeof(msg), 0, (const sockaddr *)generic_addr, sizeof(broadcast));
        }
        sleep(1);
    }

    args->alt_tv = alttv;
    args->tv = tv;
    args->time_begin = begin;
    args->socket_fd = sockfd;
    args->log_file = &logfile;

    recvfrom(sockfd, node_message, sizeof(node_message), 0, (struct sockaddr *)&client_address, &client_struct_size); // clears socket of data we passed it earlier
    if (am_root_node)
    {
        pthread_create(&root_thread, NULL, root_node, args);
        while (true)
        {
            if (pthread_detach(root_thread) == 0)
            {
                break;
            }
        }
    }
    else
    {
        pr = {sched_get_priority_max(SCHED_FIFO)};
        priority = &pr;
        pthread_create(&leaf_thread, NULL, leaf_node, args);
        while (true)
        {
            if (pthread_detach(leaf_thread) == 0)
            {
                break;
            }
        }
    }

    pthread_exit(NULL);
}
#endif

// Unit testing code for LML
// g++ -DLML_TEST -std=c++17 -Wall -Wextra NodeRoutine.cpp -o lml_test -lcpr
// ./lml_test
#ifdef LML_TEST
int main()
{
    // Define packet data to simulate a typical input, customize if needed
    std::map<std::string, std::string> packetData = {
        {"type", "calibration"},
        {"data", "100"}};
    std::string packet = LML::createPacket(packetData);
    std::cout << "Created Packet: " << packet << std::endl;
    auto parsedPacket = LML::parsePacket(packet);
    std::cout << "Parsed Packet: ";

    for (const auto &p : parsedPacket)
    {
        std::cout << p.first << " => " << p.second << ", ";
    }
    std::cout << std::endl;
    int result = LML::handlePacket(parsedPacket);
    std::cout << "Handle Packet Result: " << result << std::endl;

    return 0;
}
#endif