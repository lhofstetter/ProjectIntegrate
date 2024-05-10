#include <ESP8266WiFi.h>

const char *ssid = "yourSSID";
const char *password = "yourPASSWORD";

WiFiClient client;

void setup()
{
    Serial.begin(115200); // Match the baud rate with ESP32 (duh)
    WiFi.begin(ssid, password);

    while (WiFi.status() != WL_CONNECTED)
    {
        delay(500);
        Serial.print(".");
    }

    Serial.println("WiFi connected");
    Serial.println("IP address: ");
    Serial.println(WiFi.localIP());
}

void loop()
{
    if (Serial.available())
    {
        String data = Serial.readString(); // Read data from ESP32

        // FINISH TO SEND OVER WIFI
        Serial.print("Received: ");
        Serial.println(data);
    }
}
