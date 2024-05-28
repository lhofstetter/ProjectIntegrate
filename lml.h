#ifndef LML_H
#define LML_H

#include <sstream>
#include <iostream>
#include <string>
#include <map>
#include <fstream>

namespace LML
{
    std::string createPacket(const std::map<std::string, std::string> &data);
    std::map<std::string, std::string> parsePacket(const std::string &packet);
    int handlePacket(const std::map<std::string, std::string> &packet);
}

#endif
