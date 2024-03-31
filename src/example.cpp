#include <Arduino.h>
#include <WiFi.h>

#include "matter_ble_server.h"

#define BUTTON_PIN 39
#define LOG Serial

void setup() {
  LOG.begin(115200);

  pinMode(BUTTON_PIN, INPUT);
  if (!digitalRead(BUTTON_PIN)) {
    LOG.println("Erase WiFi settings");
    WiFi.eraseAP();
  }

  if (WiFi.begin() == WL_CONNECT_FAILED) {
    LOG.println("Starting Matter PASE");

    char qr[32];
    get_qr_code_string(qr, MATTER_VENDOR_ID, MATTER_PRODUCT_ID,
                       DEVICE_DISCRIMINATOR, MATTER_PASSCODE);
    LOG.print(
        "QR: https://chart.apis.google.com/chart?chs=200x200&cht=qr&chl=");
    LOG.println(qr);
    wait_for_commissioning_complete();
  } else {
    LOG.println("Already configured");
    while (WiFi.status() != WL_CONNECTED) {
      LOG.print(".");
      delay(1000);
    }
    LOG.println();
  }

  LOG.println("WiFi Connected");
  LOG.print(" SSID: ");
  LOG.println(WiFi.SSID());
  LOG.print(" IP address: ");
  LOG.println(WiFi.localIP());
}

void loop() {}
