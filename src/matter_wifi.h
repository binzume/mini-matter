#pragma once
#define MAX_WIFI_SSID_LEN 32
#define MAX_WIFI_PASS_LEN 32

void wifi_setup(const char* ssid, const char* password);
bool wifi_connect();
