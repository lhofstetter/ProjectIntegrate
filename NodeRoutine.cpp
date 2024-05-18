// Constant Definitions
#include "NodeDefinitions.h"

using namespace std;

const int placeholder_noise = -75;

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

    std::regex noise_regex(R"(Noise level=(-?\d+))");
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
        logfile.open("log.txt", std::ios_base::out);
        logmsg(begin, &alttv, &logfile, "Log opened successfully.", false);
    }
    catch (ifstream::failure e)
    {
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

    if (sockfd < 0)
    {
        logmsg(begin, &alttv, &logfile, "Socket creation failed. Exiting. ", false);
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

    /*
        LML Protocol:
        {
            type: pairing | signal_data | candidate | configure,
            noise: noise_level_in_dB, (this will hopefully, at least in the future, allow us to assign a weight to each distance calc on how much we can rely on it, this
            also allows us to change protocol if the channel is noisy)
            data: {
                IF type = signal_data
                devices: {
                    name_of_device: distance_from_device
                }
                ELSE IF type = candidate
                device: device_name,
                action: add | remove,
                ELSE IF type = configure
                action: disconnect | change_port | change_protocol,
                port: number_of_port (if action = change_port or change_protocol),
                protocol: 0 | 1 (0 = UDP, 1 = TCP. Port num must also be included. Only used if action = change_protocol)
                ELSE
                socket_to_communicate: socket_number, (only sent if from parent to child)
                type_of_socket_used_for_communication: 0 | 1, (0 = UDP, 1 = TCP, allows for flexible transport layer configuration)
                interval: x ms, (interval rate that the node should send data to parent, only sent from parent to child)
            }
        }

    */

    string msg = "{\n type:\"pairing\",\n noise:" + to_string(placeholder_noise) + "\n}";

    sockaddr_in6 broadcast;
    in6_addr broadcast_addr;

    unsigned char buf[sizeof(struct in6_addr)];

    inet_pton(AF_INET6, "ff02::1", buf);

    while ((epoch_double(&alttv) - connection_wait_begin) < DEFAULT_WAIT)
    { // waiting for other nodes to pair
        if (recvfrom(sockfd, node_message, sizeof(node_message), 0, (struct sockaddr *)&client_address, &client_struct_size) > 0)
        {
            // look for IS_PARENT: TRUE,
            string parent_line;
            int i = 3; // starting byte of actual packet data (after {\n )
            for (; i < 18; i++)
            {
                parent_line += string(1, node_message[i]);
            }

            if (parent_line == "IS_PARENT: TRUE")
            {
                logmsg(begin, &alttv, &logfile, "Parent node detected. Beginning pairing process...", true);
                break;
            }
            else
            {
                // not the parent, so must be another node looking to pair with parent. Ignore the message
                memset(node_message, '\0', sizeof(node_message));
            }
        }
    }

    if (node_message[0] == '\0')
    {
        logmsg(begin, &alttv, &logfile, "No node found. Assuming current node is parent.", true);

        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_if_t *devices;

        /* parent code  */
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
                { // found wireless adapter that is not currently connected to Wi-Fi network
                    break;
                }
                node = node->next;
            }

            if (node->next != NULL)
            { // successfully found wireless adapter
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
                    // implement thread logic for monitor and sending threads
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
        /* child code goes here */

        // send data through socket to address of parent
    }

    int noise_level = get_noise_level("wlan0"); // Add wireless interface here

    // Govee command payload?? Will this work??
    std::string api_key = "your_api_key";     // API KEY HERE
    std::string device_id = "your_device_id"; // Figure out how we are using device ID
    std::string message = "{"
                          "\"device\": \"" +
                          device_id + "\","
                                      "\"model\": \"H6159\","
                                      "\"cmd\": {"
                                      "\"name\": \"turn\","
                                      "\"value\": \"on\""
                                      "}"
                                      "}";

    std::string ip = "192.168.1.100"; // We need target IP here
    int port = 12345;                 // Target port here later

    if (noise_level < -80) // Adjust threshold if need!
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