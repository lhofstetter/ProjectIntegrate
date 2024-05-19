// Constant Definitions
#include "NodeDefinitions.h"

using namespace std;

const int placeholder_noise = -75;

const string LML_Types[] = {"type", "noise", "candidate", "signal_data", "device", "action", "configure", "port", "protocol", "name_of_device", "devices", "socket_to_communicate", "type_of_socket_used_for_communication", "interval"};

map<string, string> parse_json(char *node_msg)
{
    map<string, string> m;

    static int i;
    string current_str = "";
    for (i = 0; i < sizeof(node_msg); i++)
    {
        current_str += string(1, node_msg[i]);
        if (current_str == "{\n" || current_str == ",\n")
        {
            current_str = "";
        }

        static int y;
        if (current_str.length() >= 4)
        {
            for (y = 0; LML_Types->size(); y++)
            {
                if (current_str.find(LML_Types[y] + ":"))
                {
                    current_str = "";
                    static int x;

                    for (x = i; node_msg[x] != '\n'; x++)
                    {
                        current_str += string(1, node_msg[x]);
                    }

                    m[LML_Types[y]] = current_str;
                    i = x + 1;
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
// Function to execute a shell command and return its output
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

// Function to get the noise level of a network interface
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
// Function to send a UDP packet
void send_udp_packet(const std::string &message, const std::string &ip, int port)
{
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
    {
        perror("socket");
        return;
    }

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &server_addr.sin_addr);

    sendto(sockfd, message.c_str(), message.size(), 0, (struct sockaddr *)&server_addr, sizeof(server_addr));
    close(sockfd);
}

// Function to send a TCP packet
void send_tcp_packet(const std::string &message, const std::string &ip, int port)
{
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        perror("socket");
        return;
    }

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &server_addr.sin_addr);

    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("connect");
        close(sockfd);
        return;
    }

    send(sockfd, message.c_str(), message.size(), 0);
    close(sockfd);
}
void govee_api_call()
{
    string api_key = "need API key here";
    string device_id = "your_device_id";
    string message = "{\"device\": \"" + device_id + "\", \"model\": \"H6008\", \"cmd\": {\"name\": \"turn\", \"value\": \"on\"}}";
    string ip = "192.168.1.100"; // API server IP?????
    int port = 4003;

    cout << "Sending UDP packet for API call." << endl;
    send_udp_packet(message, ip, port);
}

void *parent_node(void *arg)
{
    cout << "Parent node thread running." << endl;
    govee_api_call();
    return NULL;
}

int main()
{
    cout << "-------------------------- Project Integrate --------------------------" << endl;
    fstream logfile;
    struct timespec tv;
    struct timespec alttv;
    double begin = epoch_double(&tv); // get timestamp for logging log message times.

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

    if (bind(sockfd, (struct sockaddr *)&address, sizeof(address)) < 0)
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
    char *msg;
    sprintf(msg, "{\n type:\"pairing\",\n noise:%d\n}", placeholder_noise);

    const sockaddr *generic_addr = reinterpret_cast<const sockaddr *>(&broadcast);

    sendto(sockfd, msg, sizeof(msg), 0, (const sockaddr *)generic_addr, sizeof(generic_addr));

    while ((epoch_double(&alttv) - connection_wait_begin) < DEFAULT_WAIT)
    { // waiting for other nodes to pair
        if (recvfrom(sockfd, node_message, sizeof(node_message), 0, (struct sockaddr *)&client_address, &client_struct_size) > 0)
        {
            // look for IS_PARENT: TRUE,
            map<string, string> packet = parse_json(node_message);
            auto key_value = packet.find("socket_to_communicate");

            if (key_value != packet.end())
            {
                logmsg(begin, &alttv, &logfile, "Parent node detected. Beginning pairing process...", true);
                break;
            }
            // not the parent, so must be another node. Ignore the message
            memset(node_message, '\0', sizeof(node_message));
        }
        else
        {
            sendto(sockfd, msg, sizeof(msg), 0, (const sockaddr *)generic_addr, sizeof(generic_addr));
        }
    }

    if (node_message[0] == '\0')
    {
        logmsg(begin, &alttv, &logfile, "No node found. Assuming current node is parent.", true);

        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_if_t *devices;

        if (pcap_findalldevs(&devices, errbuf) == PCAP_ERROR)
        {
            logmsg(begin, &alttv, &logfile, "ERROR: findalldevs call failed. \n Defaulting to " + string(DEFAULT_INTERFACE) + " will result in decreased effectiveness of system, and is currently unsupported. Please reboot the Pi.", true, 2);
            logfile.close();
            close(sockfd);
            exit(1);
        }
        else
        {
            pcap_if_t *node = devices;
            while (node->next != NULL)
            {
                if ((node->flags & PCAP_IF_WIRELESS) && (node->flags & PCAP_IF_CONNECTION_STATUS_DISCONNECTED))
                {
                    break;
                }
                node = node->next;
            }

            if (node->next != NULL)
            {
                char *interface = node->name;
                logmsg(begin, &alttv, &logfile, "Interface using wireless adapter found under " + string(interface) + ".", false);
                pcap_t *device = pcap_create(interface, errbuf);
                pcap_setnonblock(device, 0, errbuf);

                if (pcap_can_set_rfmon(device) <= 0)
                {
                    logmsg(begin, &alttv, &logfile, "ERROR: " + string(interface) + " is incapable of monitor mode. Please double check driver install.", true, 2);
                    pcap_freealldevs(devices);
                    logfile.close();
                    close(sockfd);
                    exit(1);
                }
                else
                {
                    if (pcap_set_rfmon(device, 1) != 0)
                    {
                        logmsg(begin, &alttv, &logfile, "ERROR: Failed to set monitor mode on " + string(interface) + ". Please double check driver install or reboot Pi.", true, 2);
                        pcap_freealldevs(devices);
                        logfile.close();
                        close(sockfd);
                        exit(1);
                    }
                }
            }
            else
            {
                logmsg(begin, &alttv, &logfile, "ERROR: No alternate wireless adapter found. Using " + string(DEFAULT_INTERFACE) + " will result in decreased effectiveness of system, and is currently unsupported. Please plug in the wireless adapter and reboot the Pi.", true, 2);

                logfile.close();
                close(sockfd);
                pcap_freealldevs(devices);
                exit(1);
            }
        }
    }
    else
    {
        logmsg(begin, &alttv, &logfile, "Node detected.", true);
        // send data through socket to address of parent
    }

    int noise_level = get_noise_level("wlan0"); // Add wireless interface here

    string api_key = "your_api_key";     // API KEY HERE
    string device_id = "your_device_id"; // Figure out how we are using device ID
    string message = "{"
                     "\"device\": \"" +
                     device_id + "\","
                                 "\"model\": \"H6008\","
                                 "\"cmd\": {"
                                 "\"name\": \"turn\","
                                 "\"value\": \"on\""
                                 "}"
                                 "}";

    string ip = "192.168.1.100"; // We need target IP here
    int port = 4003;             // Target port here later

    if (noise_level < -80) // Adjust threshold if needed!
    {
        logmsg(begin, &alttv, &logfile, "Network noise is low. Using UDP.", true);
        send_udp_packet(message, ip, port);
    }
    else
    {
        logmsg(begin, &alttv, &logfile, "Network noise is high. Using TCP.", true);
        send_tcp_packet(message, ip, port);
    }

    logfile.close();
    close(sockfd);

    return 0;
}
