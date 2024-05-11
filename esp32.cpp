#include "WiFi.h"

void setup()
{
    Serial.begin(115200); // Start serial communication at 115200 baud rate
                          // Initialize monitor mode here (not done yet)
}

void loop()
{
    // Simulate some data capture
    String packetData = "Hello ESP8266"; // Dummy packet data

    // Send data to ESP8266 via Serial
    Serial.println(packetData);

    delay(2000); // Delay for demonstration purposes
}
