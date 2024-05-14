/*
sudo apt-get update
sudo apt-get install libpcap-dev libcurl4-openssl-dev g++ tcpdump libjson-c-dev sqlite3 libsqlite3-dev
sudo ifconfig wlan0 down
sudo iwconfig wlan0 mode monitor
sudo ifconfig wlan0 up
g++ -o sniffy sniffy-sql.cpp -lpcap -lcurl -lpthread -ljson-c -lsqlite3
sudo ./sniffy
*/

#include <iostream>
#include <fstream>
#include <pthread.h>
#include <unistd.h>
#include <pcap.h>
#include <cstring>
#include <curl/curl.h>
#include <netinet/ip_icmp.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <map>
#include <cmath>
#include <sqlite3.h>
#include <vector>

std::ofstream logFile("sniffy.log", std::ios::app);

void log(const std::string &message)
{
    logFile << message << std::endl;
    std::cout << message << std::endl;
}

struct DeviceConfig
{
    std::string apiKey;
    std::string deviceId;
    std::string modelId;
};

void control_govee_device(bool turnOn, const DeviceConfig &config)
{
    CURL *curl = curl_easy_init();
    if (curl)
    {
        std::string data = "{\"device\": \"" + config.deviceId + "\", \"model\": \"" + config.modelId + "\", \"cmd\": {\"name\": \"turn\", \"value\": \"" + std::string(turnOn ? "on" : "off") + "\"}}";
        struct curl_slist *headers = nullptr;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        headers = curl_slist_append(headers, ("Govee-API-Key: " + config.apiKey).c_str());

        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_URL, "https://developer-api.govee.com/v1/devices/control");
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data.c_str());

        CURLcode res = curl_easy_perform(curl);
        if (res != CURLE_OK)
        {
            log("Sniffy: curl_easy_perform() failed: " + std::string(curl_easy_strerror(res)));
        }

        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    }
}

double calculateDistance(int rssi, int txPower)
{
    if (rssi == 0)
        return -1.0;
    double ratio = rssi * 1.0 / txPower;
    if (ratio < 1.0)
        return pow(ratio, 10);
    else
        return (0.89976) * pow(ratio, 7.7095) + 0.111;
}

void *ping_device(void *arg)
{
    std::string ip_address = *(std::string *)arg;
    std::string command = "ping -c 1 " + ip_address;
    while (true)
    {
        system(command.c_str());
        log("Sniffy: Ping sent to " + ip_address);
        sleep(1); // Ping every second
    }
    return nullptr;
}

void *monitor_rssi(void *arg)
{
    DeviceConfig config = *(DeviceConfig *)arg;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live("wlan0", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL)
    {
        log("Sniffy: pcap_open_live() failed: " + std::string(errbuf));
        return nullptr;
    }

    int rssi = -70;                                 // Example RSSI value
    double distance = calculateDistance(rssi, -50); // RSSI at 1m needs to be measured
    log("Distance to device: " + std::to_string(distance) + " meters");

    control_govee_device(true, config);

    pcap_close(handle);
    return nullptr;
}

std::map<std::string, DeviceConfig> loadDeviceConfigs(const std::string &dbFile)
{
    std::map<std::string, DeviceConfig> configs;
    sqlite3 *db;
    sqlite3_open(dbFile.c_str(), &db);
    sqlite3_stmt *stmt;
    const char *sql = "SELECT name, apiKey, deviceId, modelId FROM devices";

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK)
    {
        while (sqlite3_step(stmt) == SQLITE_ROW)
        {
            DeviceConfig config;
            config.apiKey = std::string(reinterpret_cast<const char *>(sqlite3_column_text(stmt, 1)));
            config.deviceId = std::string(reinterpret_cast<const char *>(sqlite3_column_text(stmt, 2)));
            config.modelId = std::string(reinterpret_cast<const char *>(sqlite3_column_text(stmt, 3)));
            configs[std::string(reinterpret_cast<const char *>(sqlite3_column_text(stmt, 0)))] = config;
        }
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return configs;
}

int main()
{
    std::string dbFile = "configurations.db"; // SQLite database file
    auto deviceConfigs = loadDeviceConfigs(dbFile);
    std::vector<pthread_t> threads;

    for (const auto &configPair : deviceConfigs)
    {
        pthread_t thread1, thread2;

        // Create and start the ping_device thread
        std::string *ip_address = new std::string("192.168.1.1"); // Placeholder IP address
        if (pthread_create(&thread1, nullptr, ping_device, (void *)ip_address) != 0)
        {
            log("Sniffy: Failed to create ping_device thread for device " + configPair.first);
            continue;
        }
        threads.push_back(thread1);

        // Create and start the monitor_rssi thread
        if (pthread_create(&thread2, nullptr, monitor_rssi, (void *)&configPair.second) != 0)
        {
            log("Sniffy: Failed to create monitor_rssi thread for device " + configPair.first);
            continue;
        }
        threads.push_back(thread2);
    }

    for (auto &thread : threads)
    {
        pthread_join(thread, nullptr);
    }

    return 0;
}
