#Compiler Options
#sudo apt-get install libcurl4-openssl-dev (rasp)
CC = g++
CFLAGS = -Wall -Wextra -std=c++17
LDFLAGS = -lpcap -lpthread -lcurl 

#Targets
all : RSSI NodeRoutine

%.o: %.cpp NodeDefinitions.h
	$(CC) $(CFLAGS) -c $< -o $@

RSSI: RSSI.o
	$(CC) $^ -o $@ $(LDFLAGS)

NodeRoutine: NodeRoutine.o 
	$(CC) $^ -o $@ $(LDFLAGS)
	
RSSI.o: RSSI.cpp
NodeRoutine.o: NodeRoutine.cpp

clean:
	rm -f *.o RSSI NodeRoutine lml_test log.txt