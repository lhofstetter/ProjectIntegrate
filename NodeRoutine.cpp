#include "NodeDefinitions.h"

using namespace std;

const string LML_Types[] = {"type", "noise", "candidate", "signal_data", "device", "action", "configure", "port", "protocol", "name_of_device", "devices", "socket_to_communicate", "type_of_socket_used_for_communication", "interval"};

struct LeafDetails
{
    int port;
    string ipAddress;
    int identifierNumber;
    int socket;
    int interval;
    map<string, int> distanceFromSiblings;
};

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

map<string, LeafDetails> leaf_details;

sched_param pr = {sched_get_priority_max(SCHED_RR)};
const sched_param *priority = &pr;

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

void alertSystem(const std::string &message)
{
    std::cerr << "Alert: " << message << std::endl;
    // More implementation in the future, example SMS text
}

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

std::string exec(const char *cmd)
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

int get_noise_level(const std::string &interface)
{
    std::string command = "iwconfig " + interface;
    std::string output = exec(command.c_str());

    std::regex noise_regex("(Noise level=(-?\\d+))");
    std::smatch match;
    int noise_level = -1;

    if (std::regex_search(output, match, noise_regex) && match.size() > 1)
    {
        noise_level = std::stoi(match.str(1));
    }

    return noise_level;
}

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
/*
void govee_api(const std::string &api_key = "", const std::string &device_id = "", const std::string &action = "", const std::string &value = "")
{
    Url url = "https://developer-api.govee.com/v1/devices/control";
    Header headers = {{"Content-Type", "application/json"}, {"Govee-API-Key", api_key}};
    Body body = "{\"device\": \"" + device_id + "\", \"model\": \"H6008\", \"cmd\": {\"name\": \"" + action + "\", \"value\": \"" + value + "\"}}";

    Response r = Post(url, headers, body);
    std::cout << "Status code: " << r.status_code << std::endl;
    std::cout << "Response body: " << r.text << std::endl;
}
*/
// Shortcut function to determine best protocol if needed
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
                                if (buf == sender_address.sin6_addr.__u6_addr.__u6_addr8)
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

    /*
        Need to begin sniffer thread here before entering while loop for socket operations.
        That means we need to make the shared memory buffer and everything else that the leaf and sniffer both need to communicate.
    */

    while (true)
    { // this is probably gonna end up as a simple event-driven system - in order to enable it to respond to different messages from root.
        double interval_start = epoch_double(&ints_tv);
        while (epoch_double(&ints_tv) - interval_start < arguments->interval)
        { // could potentially miss an interval deadline because multithreading, but it shouldn't matter because the
            // root shouldn't actually impose the deadline - that just gives the root a way of communicating to leaves to "space out" their packets so processing can be done before receiving another packet.
        }
    }

    close(sock);
    return NULL;
}

#ifndef LML_TEST
int main()
{
    cout << "-------------------------- Project Integrate --------------------------" << endl;
    Args *args = (struct Args *)malloc(sizeof(struct Args));
    fstream logfile;
    struct timespec tv, alttv;
    double begin = epoch_double(&tv);
    char node_message[200];
    memset(node_message, '\0', sizeof(node_message));

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

    pthread_t root_thread, leaf_thread;
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