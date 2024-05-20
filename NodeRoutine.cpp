#include "NodeDefinitions.h"

using namespace std;
using namespace cpr;

// const int placeholder_noise = -75;

const string LML_Types[] = {"type", "noise", "candidate", "signal_data", "device", "action", "configure", "port", "protocol", "name_of_device", "devices", "socket_to_communicate", "type_of_socket_used_for_communication", "interval"};

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
            for (int y = 0; y < sizeof(LML_Types) / sizeof(LML_Types[0]); y++)
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
// govee_api_call(api_key, device_id, "turn", "on");
// govee_api_call(api_key, device_id, "turn", "off");
void govee_api_call(const std::string &api_key = "", const std::string &device_id = "", const std::string &action = "", const std::string &value = "")
{
    Url url = "https://developer-api.govee.com/v1/devices/control";
    Header headers = {{"Content-Type", "application/json"}, {"Govee-API-Key", api_key}};
    Body body = "{\"device\": \"" + device_id + "\", \"model\": \"H6008\", \"cmd\": {\"name\": \"" + action + "\", \"value\": \"" + value + "\"}}";

    Response r = Post(url, headers, body);
    std::cout << "Status code: " << r.status_code << std::endl;
    std::cout << "Response body: " << r.text << std::endl;
}

void handle_communication(const string &message, const string &ip, int port, int noise_level)
{
    if (noise_level < -80)
    { // Check noise level and decide communication protocol
        cout << "Low noise level detected. Using UDP for communication." << endl;
        send_udp_packet(message, ip, port);
    }
    else
    {
        cout << "High noise level detected. Using TCP for communication." << endl;
        send_tcp_packet(message, ip, port);
    }
}
void *parent_node(void *arg)
{
    cout << "Parent node thread running." << endl;
    // govee_api_call();
    return NULL;
}

void *child_node(void *arg)
{
    cout << "Child node thread running." << endl;

    int noise_level = get_noise_level("wlan0"); // change einterface

    // some sort of details here
    // handle_communication(message, ip, port, noise_level);
    return NULL;
}

int main()
{
    cout << "-------------------------- Project Integrate --------------------------" << endl;
    fstream logfile;
    struct timespec tv, alttv;
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
    // snprintf(msg, "{\n type:\"pairing\",\n noise:%d\n}", placeholder_noise);

    const sockaddr *generic_addr = reinterpret_cast<const sockaddr *>(&broadcast);

    sendto(sockfd, msg, sizeof(msg), 0, (const sockaddr *)generic_addr, sizeof(broadcast));

    pthread_t parent_thread, child_thread;

    map<string, string> packet;

    while ((epoch_double(&alttv) - connection_wait_begin) < DEFAULT_WAIT)
    {
        if (recvfrom(sockfd, node_message, sizeof(node_message), 0, (struct sockaddr *)&client_address, &client_struct_size) > 0)
        {
            packet = parse_json(node_message);
            if (packet.find("socket_to_communicate") != packet.end())
            {
                pthread_create(&parent_thread, NULL, parent_node, NULL);
                pthread_join(parent_thread, NULL);
                break;
            } else if (packet.find("child_flag") != packet.end() && packet["child_flag"] == "true") { // "pairing" with a child in order to get distance from that node
                //pthread_create()
            }
        }
        else
        {
            sendto(sockfd, msg, sizeof(msg), 0, (const sockaddr *)generic_addr, sizeof(broadcast));
        }
    }

    if (node_message[0] == '\0')
    {
        logmsg(begin, &alttv, &logfile, "No node found. Assuming current node is parent.", true);
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_if_t *devices;

        if (pcap_findalldevs(&devices, errbuf) == PCAP_ERROR)
        {
            logmsg(begin, &alttv, &logfile, "ERROR: findalldevs call failed. Defaulting to " + string(DEFAULT_INTERFACE) + " will result in decreased effectiveness of system, and is currently unsupported. Please reboot the Pi.", true, 2);
            logfile.close();
            close(sockfd);
            exit(1);
        }

        pcap_if_t *node = devices;
        while (node != NULL && !(node->flags & PCAP_IF_WIRELESS))
        {
            node = node->next;
        }

        if (node != NULL)
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
            pcap_freealldevs(devices);
            logfile.close();
            close(sockfd);
            exit(1);
        }
    }
    else
    {
        pthread_create(&child_thread, NULL, child_node, NULL);
        pthread_join(child_thread, NULL);
    }

    logfile.close();
    close(sockfd);

    return 0;
}
