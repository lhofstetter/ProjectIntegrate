// g++ -DLML_TEST -std=c++17 -Wall -Wextra lml.cpp -o lml_test
#include "lml.h"

// Logging error messages to both standard error and a log file.
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

// Sending alert notifications to a system administrator.
void alertSystem(const std::string &message)
{
    std::cerr << "Alert: " << message << std::endl;
    // Additional implementation, sending SMS notifications? App?
}

namespace LML
{
    // Creates a packet from a map of string key-value pairs.
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

    // Parses a packet into a map of key-value pairs from a JSON-like string.
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

    // Directs the packet to appropriate processing functions based on its type.
    int handlePacket(const std::map<std::string, std::string> &packet)
    {
        auto it = packet.find("type");
        if (it == packet.end())
        {
            std::cerr << "Packet type not specified." << std::endl;
            logError("Packet received without a type specified.");
            return -1; // Signal error.
        }

        const std::string &type = it->second;
        if (type == "pairing")
        {
            std::cout << "Processing Pairing Packet." << std::endl;
            return 0; // Signal success.
        }
        else if (type == "calibration")
        {
            std::cout << "Processing Calibration Packet." << std::endl;
            return 0; // Signal success.
        }
        else if (type == "signal_data")
        {
            std::cout << "Processing Signal Data Packet." << std::endl;
            return 0; // Signal success.
        }
        else
        {
            std::cerr << "Error: Unhandled packet type '" << type << "' received." << std::endl;
            logError("Unhandled packet type encountered: " + type);
            alertSystem("Received an unrecognized packet type, which requires manual inspection. Type: " + type);
            return -1; // Signal error.
        }
    }

}

#ifdef LML_TEST
// FOR STANDALONE TESTING SO FAR:
int main()
{
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

    LML::handlePacket(parsedPacket);

    return 0;
}
#endif
