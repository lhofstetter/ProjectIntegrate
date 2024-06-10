#Compiler Options
#sudo apt-get install libcurl4-openssl-dev (rasp)
CC = g++
CFLAGS = -Wall -Wextra -std=c++17
LDFLAGS = -lpcap -lpthread -lcurl 

#Targets
all : NodeRoutine

%.o: %.cpp NodeDefinitions.h
	$(CC) $(CFLAGS) -c $< -o $@

NodeRoutine: NodeRoutine.o 
	$(CC) $^ -o $@ $(LDFLAGS)
	
NodeRoutine.o: NodeRoutine.cpp

clean:
	rm -f *.o NodeRoutine lml_test log.txt rssi.txt