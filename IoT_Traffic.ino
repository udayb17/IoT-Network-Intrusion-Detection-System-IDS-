#include <WiFi.h>
#include <PubSubClient.h>

// WiFi Configuration
const char* ssid = "Mi 10i";   //  WiFi name
const char* password = "";             // If no password then keep it EMPTY for open WiFi

// MQTT Configuration
const char* mqtt_server = "10.113.133.11";   // <-- YOUR LAPTOP IP address in which mqtt is working
const int mqtt_port = 1883;  //it uses default as port no 1883
const char* mqtt_topic = "iot/sensor"; //it will send traffic as iot/sensor

// WiFi & MQTT Objects              
WiFiClient espClient;  // wifi client created named espclient
PubSubClient client(espClient);   //mqtt client created named client with espclient

// WiFi Connection Function
void connectToWiFi() {   // this function will connect esp with the wifi
  Serial.println("Connecting to WiFi...");
  WiFi.begin(ssid, password);

  int attempt = 0;
  while (WiFi.status() != WL_CONNECTED) {  //it will run until the wifi isn't connected
    delay(500);
    Serial.print(".");
    attempt++;

    if (attempt > 20) {   // 10 seconds timeout after that it will print failed 
      Serial.println("\n❌ WiFi FAILED");
      Serial.println("Check WiFi name / network type");
      return;
    }
  }

  Serial.println("\n✅ WiFi Connected!");
  Serial.print("ESP32 IP: ");
  Serial.println(WiFi.localIP());
}

// MQTT Reconnect Function
void reconnectMQTT() {  // this function will now connected the esp to mqtt . so,that it will be available to send traffic
  while (!client.connected()) { //it will run until the mqtt isn't connected 
    Serial.print("Connecting to MQTT... ");
    if (client.connect("ESP32_IOT_Client")) {
      Serial.println("✅ MQTT Connected");
    } else {
      Serial.print("Failed, rc="); //it will print it until mqtt isn't connected 
      Serial.print(client.state());
      Serial.println(" retrying in 2 seconds");
      delay(2000);
    }
  }
}

// SETUP
void setup() {  //it will run only after esp32 starts
  Serial.begin(115200);  // starts serial monitor communication
  delay(1000);

  connectToWiFi();

  client.setServer(mqtt_server, mqtt_port);
}

// LOOP
void loop() {   // this function will run continuously
  if (!client.connected()) {  //
    reconnectMQTT();
  }
  client.loop();

  // Generate dummy IoT data
  int temperature = random(25, 35);
  int humidity = random(40, 70);

  //  Create JSON payload 
  String payload = "{";
  payload += "\"temperature\":";
  payload += temperature;
  payload += ",\"humidity\":";
  payload += humidity;
  payload += "}";

  // Publish data , sends data to mqtt
  client.publish(mqtt_topic, payload.c_str());

  // Print on Serial Monitor
  Serial.print("Published: ");
  Serial.println(payload);

  delay(1000);  // Send data every 1 second
}
