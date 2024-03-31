#ifdef ESP32

#include <WiFi.h>

void wifi_setup(const char* ssid, const char* password) {
  WiFi.begin(ssid, password);
}

bool wifi_connect() {
  while (!WiFi.status() || WiFi.status() >= WL_DISCONNECTED) {
    delay(200);
  }
  return WiFi.status() == WL_CONNECTED;
}

#endif
