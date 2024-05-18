#Compiler Options
CC = g++
CFLAGS = -Wall -Wextra -std=c++11
LDFLAGS = -lpcap

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
	rm -f *.o RSSI NodeRoutine