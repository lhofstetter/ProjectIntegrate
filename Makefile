#Compiler Options
CC = g++
CFLAGS = -Wall -Wextra -std=c++17
LDFLAGS = -lpcap -lpthread -lcpr 

#Targets
all : RSSI NodeRoutine

%.o: %.cpp NodeDefinitions.h
	$(CC) $(CFLAGS) -c $< -o $@

RSSI: RSSI.o
	$(CC) $^ -o $@ $(LDFLAGS)

NodeRoutine: NodeRoutine.o lml.o
	$(CC) $^ -o $@ $(LDFLAGS)
	
RSSI.o: RSSI.cpp
NodeRoutine.o: NodeRoutine.cpp

LML.o: lml.cpp lml.h
	$(CC) $(CFLAGS) -c lml.cpp -o LML.o

clean:
	rm -f *.o RSSI NodeRoutine