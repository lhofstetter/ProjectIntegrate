#include "NodeDefinitions.h"

using namespace std;

vector<string> deviceIDs = {"device_id_1", "device_id_2", "device_id_3"};
sched_param pr = {sched_get_priority_max(SCHED_RR)};
const sched_param *priority = &pr;
sched_param pr1 = {sched_get_priority_max(SCHED_FIFO) - 1};
const sched_param * priority1 = &pr1;
const unsigned char LML_types[] = {0b000, 0b001, 0b010, 0b011, 0b100, 0b101, 0b110, 0b111};
unsigned char noise_level;
unsigned char interval;
double global_begin = 0.0;
int received_packet_count = 0;
pthread_mutex_t capture_lock; 


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
    u_char unique_name;
    u_char mac_addr[6];
    int8_t rssi;
    char oui[9];
    float distance;
} capture;

struct candidate_device
{
    unsigned char name;
    char mac_addr[6];
    map<string, float> distances;
    timespec start;
    bool is_trial_device;
    bool countdown;
    int8_t counter;
} device;

struct trial_device
{
    unsigned char name;
    char mac_addr[6];
    map<string, float> distances;
    int8_t counter;
    timespec initial_encounter;
};

struct permanent_device
{
    unsigned char name;
    char mac_addr[6];
    map<string, float> distances;
    timespec last_update;
    bool currently_active;
} pd;

struct blocked_device
{
    unsigned char name;
    char mac_addr[6];
} bd;

u_char unique_name (u_char mac_addr[6]) {
    u_char name = 0b00000000;
    u_char op1;
    u_char op2;

    u_char temp_op = 0b00000001;
    for (int i = 0; i < 6; i++) {
        op1 = 0b00000000;
        op2 = 0b00000000;
        for (int x = 0; x < 4; x++) {
            if (((temp_op << x) & mac_addr[i])) {
                // this byte is 1
                op1 += (temp_op << x);
            }
        }
        for (int x = 4; x < 8; x++) {
            if (((temp_op << x) & mac_addr[i])) {
                op2 += (temp_op << x);
            }
        }
        name += (op1 & op2);
    }
    return name;
}

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

map<string, string> parse_json_v2 (string msg) {
    map<string, string> json_map;
    string current_key = "";
    string current_val = "";
    bool reached_val = false;
    bool in_key = false;

    for (int i = 0; i < msg.size(); i++) {
        if (msg[i] == '\"' || msg[i] == ' ') {
            continue;
        }
        if (msg[i] != '{' && msg[i] != '\n' && msg[i] != ',' && !in_key && !reached_val) {
            current_key += msg[i];
            in_key = true;
        } else if (in_key && !reached_val && msg[i] != ':') { // in the middle of the key
            current_key += msg[i];
        } else if (msg[i] == ':') { // we've reached the field associated with the key
            in_key = false;
            reached_val = true;
        } else if (msg[i] != '\n' && msg[i] != ',' && reached_val) { // in the middle of the value
            current_val += msg[i];
        } else { // out of the value
            json_map[current_key] = current_val;
            current_key = "";
            current_val = "";
            reached_val = false;
            in_key = false;
        }
    }
    return json_map;

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
void logRSSI(const std::string &message)
{
    std::lock_guard<std::mutex> lock(logMutex);                        // Ensuring thread safety
    std::ofstream rssi_log("rssi.txt", std::ios::out | std::ios::app); // Open file
    if (!rssi_log.is_open())
    {
        std::cerr << "Failed to open rssi.txt for logging." << std::endl;
        return;
    }
    rssi_log << message << std::endl;
    rssi_log.close(); // Close file immediately after writing
}

void checkAndRotateLog()
{
    std::lock_guard<std::mutex> lock(logMutex); // Ensuring thread safety
    const char *filename = "rssi.txt";
    std::cout << "Attempting to delete and recreate " << filename << std::endl;

    // Close and attempt to delete the file
    std::remove(filename);
    std::ofstream rssi_log(filename, std::ios::out | std::ios::app); // Re-create the file
    if (!rssi_log.is_open())
    {
        std::cerr << "Failed to reopen " << filename << std::endl;
    }
    else
    {
        std::cout << "Log file " << filename << " recreated successfully." << std::endl;
    }
}

void getDeviceID(pcap_if_t **all_devs, pcap_if_t **node_curr, char error_buff[], char **devID, bool debug)
{
    if (pcap_findalldevs(all_devs, error_buff) != 0)
    {
        logRSSI("Error finding device: " + std::string(error_buff));
        exit(1);
    }

    std::ostringstream msg;
    for (*node_curr = *all_devs; *node_curr; *node_curr = (*node_curr)->next)
    {
        if (debug)
        {
            msg << "Device: " << (*node_curr)->name << "\n";
            logRSSI(msg.str());
            msg.str(""); // Clear the stream
        }
        if (((*node_curr)->flags & PCAP_IF_WIRELESS) && ((*node_curr)->flags & PCAP_IF_RUNNING))
        {
            *devID = (*node_curr)->name;
            logRSSI("Using device: " + std::string(*devID));
            return;
        }
    }

    logRSSI("Suitable device not found.");
    exit(1);
}

void my_callback(u_char *unused, const struct pcap_pkthdr *header, const u_char *bytes)
{
    (void)unused; // Ignore unused parameter
    pthread_mutex_lock(&capture_lock);

    bpf_u_int32 packet_length = header->caplen;
    uint16_t radiotap_len = bytes[2] + (bytes[3] << 8);

    capture.rssi = (int8_t)bytes[radiotap_len - 1];
    int src_mac = radiotap_len + 10;
    char mac_addr[18];
    snprintf(mac_addr, sizeof(mac_addr), "%02x:%02x:%02x:%02x:%02x:%02x",
             bytes[src_mac], bytes[src_mac + 1], bytes[src_mac + 2], bytes[src_mac + 3],
             bytes[src_mac + 4], bytes[src_mac + 5]);

    std::ostringstream msg;
    msg << "\n---------------------------------------\n"
        << "RSSI: " << int(capture.rssi) << " dBm\n"
        << "MAC Address: " << mac_addr << "\n";

    int temp = radiotap_len + 24;
    if (static_cast<bpf_u_int32>(temp) < packet_length && bytes[temp] == 221)
    {
        char oui[9];
        snprintf(oui, sizeof(oui), "%02x:%02x:%02x", bytes[temp + 2], bytes[temp + 3], bytes[temp + 4]);
        msg << "Vendor OUI: " << oui << "\n";
    }
    else
    {
        msg << "Vendor ID not found.\n";
    }

    float static_rssi_1m = -49; // RSSI at 1 meter
    float distance = pow(10, ((static_rssi_1m - capture.rssi) / (10 * 2.5)));
    msg << "Estimated Distance: " << distance << " meters\n"
        << "---------------------------------------\n";
    
    capture.distance = distance;
    
    for (int i = 0; i < 6; i++) {
        capture.mac_addr[i] = bytes[src_mac + i];
    }

    capture.unique_name = unique_name(capture.mac_addr);
    received_packet_count++;

    pthread_mutex_unlock(&capture_lock);
    logRSSI(msg.str());

    sched_yield();
}

void *rssi_thread_func(void *args)
{
    std::cout << "RSSI Sniffer thread started." << std::endl;
    auto last_check_time = std::chrono::steady_clock::now();
    std::chrono::seconds interval(20); // Reset rssi.txt every 20 seconds
    
    if (pthread_setschedparam(pthread_self(), SCHED_FIFO, priority1) != 0)
    { // WARNING: successful scheduling policy change means we HAVE to manually yield thread from here on out
        cout << "Unable to set scheduling policy. Performance of Integrate may suffer. Please try to rerun the program with root permissions." << endl;
    }


    while (true)
    {
        auto current_time = std::chrono::steady_clock::now();
        if (current_time - last_check_time >= interval)
        {
            std::cout << "Checking and rotating log..." << std::endl;
            checkAndRotateLog();
            last_check_time = current_time; // Reset the last check time
        }

        getDeviceID(&sniffinput.alldevs, &sniffinput.node, sniffinput.error_buffer, &sniffinput.dev_ID, true);

        sniffinput.dev_handler = pcap_create(sniffinput.dev_ID, sniffinput.error_buffer);
        if (sniffinput.dev_handler == NULL)
        {
            logRSSI("Error creating handler: " + std::string(sniffinput.error_buffer));
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

        pcap_loop(sniffinput.dev_handler, 1, my_callback, NULL);
        //pcap_close(sniffinput.dev_handler);
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
    std::cout << "Channel synchronization thread started." << std::endl;
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
    socklen_t broadcast_address_len = sizeof(broadcast_addr);
    char buffer[200];
    memset(buffer, '\0', 200);


    while (paired_leaves < MAX_LEAVES) {
        string msg = "{\n\"type\":\"pairing\",\n\"noise\":\"" + to_string(get_noise_level("wlan0")) + "\",\n\"interval\":" + to_string(DEFAULT_INTERVAL + (DEFAULT_INTERVAL * paired_leaves)) + "\n}";
        // Listening for children responses

        ssize_t message_len = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&sender_address, &sender_address_len);
        cout << string(buffer) << endl;
        if (message_len > 0)
        {
            buffer[message_len] = '\0'; // @attention: @Marley why are we getting rid of the last byte?
            string response(buffer);
            map<string, string> packet = parse_json_v2(response);
            char ipv6Addr[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &(sender_address.sin6_addr), ipv6Addr, INET6_ADDRSTRLEN);
            string ipAddr = ipv6Addr;
            cout << packet["confirmation"] << endl;


            string leaf_identifier = "Leaf#" + to_string(paired_leaves + 1);
            if (packet.find("confirmation") != packet.end() && packet["confirmation"] == "true") {
                LeafDetails details = {PAIRING_PORT, ipAddr, paired_leaves + 1, DEFAULT_INTERVAL + (DEFAULT_INTERVAL * paired_leaves)};
                leaf_details[leaf_identifier] = details;
                logmsg(arguments->time_begin, &new_alt_tv, arguments->log_file, "Paired with new leaf node: " + leaf_identifier + " on port " + to_string(details.port) + " with IP " + details.ipAddress + ".", true);
                paired_leaves++;
                cout << "success" << endl;
            }
        } else {
            sendto(sock, msg.c_str(), msg.size(), 0, generic_addr, sizeof(broadcast));
        }
        sleep(1);
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
        string msg = "{\n\"type\":\"calibration\",\n\"noise\":\"" + to_string(get_noise_level(DEFAULT_INTERFACE)) + "\",\n\"num_of_calibration_packets\":" + to_string(DEFAULT_CALIBRATION_NUMBER) + ",\n\"leaf\":" + leaf_details["Leaf#" + to_string(i + 1)].ipAddress + "\n}";
        sendto(sock, msg.c_str(), msg.size(), 0, (const sockaddr *)generic_addr, sizeof(broadcast));
        sleep(10); // sleep period while waiting for leaf to begin blasting calibration packets
        bool leaves[paired_leaves - 1];
        memset(leaves, false, sizeof(leaves));
        bool cond = true;
        while (cond) {
            message_length = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&sender_address, &sender_address_len);
            if (message_length <= 0)
            {
                continue; // no message in the buffer or empty message
            }
            else
            {
                map<string, string> packet = parse_json_v2(buffer);
                if (packet.find("packets_remaining") != packet.end())
                {
                    if (stoi(packet["packets_remaining"]) == 0)
                    {
                        // the child has finished it's burst. We should now check to see if the other leaves received successfully.
                        while ((message_length = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&sender_address, &sender_address_len)) <= 0)
                        {
                            continue; // wait until there's something in the socket
                        }

                        packet = parse_json_v2(buffer);
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
    } 

    // calibration phase complete. The root now stores details for every sibling's distance from it's other siblings. We can actually
    // start doing our job now :D

    // generate candidate list. Also, the root's distance from it's leaves has not yet been determined at this phase. That happens once the
    // sniffer thread is running.

    candidate_device * candidate_list[256];
    trial_device * trial_list[256];
    permanent_device * permanent_list[256];
    blocked_device * blocklist[256];

    for (int i = 0; i < 256; i++) {
        candidate_list[i] = nullptr;
        trial_list[i] = nullptr;
        permanent_list[i] = nullptr;
        blocklist[i] = nullptr;
    }

    pthread_t sniffer_tid;

    pthread_create(&sniffer_tid, NULL, rssi_thread_func, NULL); // create sniffer thread and let it begin it's job. 
    // From now on we must assume that we are not always in control of the CPU, so keep that in mind.
    
    while (true) {
        u_char device_belongs = 0b100;

        // update with most recent packet sniffed
        if (pthread_mutex_lock(&capture_lock) == 0 && capture.unique_name != '\0') { // we've acquired the lock for the capture successfully. 
            int x = 0;
            for (int i = 0; i < 256; i++) {
                if (candidate_list[i] != nullptr && capture.unique_name == candidate_list[i]->name) {
                    device_belongs = 0b000;
                    x = i;
                    break;
                } else if (trial_list[i] != nullptr && capture.unique_name == trial_list[i] -> name) {
                    device_belongs = 0b001;
                    x = i;
                    break;
                } else if (permanent_list[i] != nullptr & capture.unique_name == permanent_list[i] -> name) {
                    device_belongs = 0b010;
                    x = i;
                    break;
                } else if (blocklist[i] != nullptr && capture.unique_name == blocklist[i] -> name) {
                    device_belongs = 0b011;
                    x = i;
                    break;
                } else if (trial_list[i] != nullptr) { // have to iterate through the trial list as we go so that x will point to the correct value.
                    x++;
                } else if (trial_list[i] == nullptr && permanent_list[i] == nullptr && blocklist[i] == nullptr && candidate_list[i] == nullptr) {
                    break; // we're out of values - go ahead and break the loop early, must be in a trial list
                }
            }

            switch (device_belongs) {
                case 0b100: // device not in any of our lists. Add to trial list.
                    trial_device * d;
                    d -> counter = 1;
                    d -> distances.insert({"root", capture.distance});
                    timespec current;
                    d -> initial_encounter = current;
                    for (int i = 0; i < 6; i++) {
                        d -> mac_addr[i] = capture.mac_addr[i];
                    }
                    trial_list[x] = d;
                    break;
                case 0b000: // already in candidate list. Update the relevant values. 
                    (candidate_list[x] -> distances)["root"] = capture.distance;
                    break;
                case 0b001: // already in trial list. Update the relevant value.
                    (trial_list[x] -> distances)["root"] = capture.distance;
                    break;
                case 0b010:
                    (permanent_list[x] -> distances)["root"] = capture.distance;
                    break;
                default: // blocked device
                    break;
            }
            // do some more stuff here I guess
            pthread_mutex_unlock(&capture_lock);
        }
    




        
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
    char buffer[200];
    sockaddr_in6 root_address = arguments->root_ip;
    socklen_t root_address_len = sizeof(root_address);
    ssize_t message_len;
    string message = "{\n\"type\":\"pairing\",\n\"noise\":\"" + to_string(get_noise_level(DEFAULT_INTERFACE)) + "\",\nconfirmation: true,\n}";

    
    if (sendto(sock, message.c_str(), sizeof(message.c_str()), 0, (struct sockaddr *)&root_address, sizeof(root_address)) == -1) {
        cout << "huh" << endl;
    }

    // confirmation for pairing with the root.

    

    // need to implement calibration phase here - with a wait until it actually begins.
    while (true)
    {
        message_len = recvfrom(sock, buffer, sizeof(&buffer), 0, (struct sockaddr *)&root_address, &root_address_len);
        if (message_len > 0)
        {
            data = parse_json_v2(buffer);
        }
    }
    double interval_start = epoch_double(&ints_tv);

    while (true)
    { // this is probably gonna end up as a simple event-driven system - in order to enable it to respond to different messages from root.
        if (epoch_double(&ints_tv) - interval_start < arguments->interval - 0.002)
        { // give the code 20 ms to send data
            message_len = recvfrom(sock, buffer, sizeof(&buffer), 0, (struct sockaddr *)&root_address, &root_address_len);
            if (message_len > 0) {
                
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

    Args *args = (struct Args *)malloc(sizeof(struct Args));
    fstream logfile;
    struct timespec tv, alttv;
    double begin = epoch_double(&tv);
    char node_message[200];
    memset(node_message, '\0', sizeof(node_message));
    struct ipv6_mreq mreq;

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

    mreq.ipv6mr_interface = if_nametoindex(DEFAULT_INTERFACE);  // Replace with the appropriate interface name
    inet_pton(AF_INET6, "ff02::1", &mreq.ipv6mr_multiaddr);
    setsockopt(sockfd, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &mreq, sizeof(mreq));
    int broadcastEnable = 1;
    int multicastLoopDisable = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, &broadcastEnable, sizeof(broadcastEnable));
    setsockopt(sockfd, SOL_SOCKET, IPV6_MULTICAST_LOOP, &multicastLoopDisable, sizeof(multicastLoopDisable));


    struct timespec connection_wait;
    double connection_wait_begin = epoch_double(&connection_wait);

    logmsg(begin, &alttv, &logfile, "Setup successful. Listening for other nodes...", true);

    sockaddr_in6 broadcast;
    struct in6_addr broadcast_addr;
    inet_pton(AF_INET6, "ff02::1", &broadcast_addr);

    broadcast.sin6_addr = broadcast_addr;
    broadcast.sin6_family = AF_INET6;
    broadcast.sin6_port = htons(PAIRING_PORT);
    string msg = "\n{\"type\":\"pairing\",\n\"noise\":" + to_string(get_noise_level(DEFAULT_INTERFACE)) + "\"\n}";

    const sockaddr *generic_addr = reinterpret_cast<const sockaddr *>(&broadcast);

    map<string, string> packet;

    bool am_root_node = true;

    while ((epoch_double(&alttv) - connection_wait_begin) < DEFAULT_WAIT)
    {
        if (recvfrom(sockfd, node_message, sizeof(node_message), MSG_PEEK, (struct sockaddr *)&client_address, &client_struct_size) > 0)
        {
            packet = parse_json_v2(node_message);
            if (packet.find("interval") != packet.end()) {
                am_root_node = false;
                args->root_ip = client_address;
                args->interval = stoi(packet["interval"]);
                break;
            } else {
                recvfrom(sockfd, node_message, sizeof(node_message), 0, (struct sockaddr *)&client_address, &client_struct_size);
            }
        }
        else
        {
            sendto(sockfd, msg.c_str(), sizeof(msg.c_str()), 0, generic_addr, sizeof(broadcast));
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

        }
    }
    else
    {
        pr = {sched_get_priority_max(SCHED_FIFO)};
        priority = &pr;
        pthread_create(&leaf_thread, NULL, leaf_node, args);
        while (true) {

        }
    }

}
#endif

// Unit testing code for LML algo
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
