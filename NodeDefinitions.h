#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/socket.h>
#include <iostream>
#include <fstream>
#include <sys/stat.h>
#include <sys/types.h>
#include <chrono>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <fcntl.h>
#include <pcap/pcap.h>
#include <unistd.h>

#define PAIRING_PORT 8082
#define DEFAULT_WAIT 10.0
#define DEFAULT_INTERFACE "eth0"

#define WARN 1
#define ERROR 2

/*
struct node {
    
};
*/