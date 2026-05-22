#include <WiFi.h>

const char* ssid = "Mi 10i";
const char* password = "";

const char* targetIP = "10.251.241.11";  // your laptop IP

WiFiClient client;

void setup() {
  Serial.begin(115200);
  WiFi.begin(ssid, password);

  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }

  Serial.println("Connected to WiFi");
}

void loop() {

  // 🔥 PORT SCAN LOOP
  for (int port = 1; port <= 100; port++) {

    if (client.connect(targetIP, port)) {
      Serial.print("Open Port: ");
      Serial.println(port);
      client.stop();
    } else {
      Serial.print("Scanning Port: ");
      Serial.println(port);
    }

    delay(10);  // speed of scan
  }

}
