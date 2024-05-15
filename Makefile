CC = g++
CFLAGS = -lpcap
OBJ = RSSI.cpp

RSSI: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)

clean:
	rm -f $(OBJ)