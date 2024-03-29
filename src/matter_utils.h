#define MATTER_DEBUG_LOG

#ifdef MATTER_DEBUG_LOG
#include <Arduino.h>

static void debug_dump(const char *msg, const uint8_t *buf = nullptr,
                       int len = 0) {
  if (msg) {
    Serial.print(msg);
    Serial.print(": ");
  }
  for (int i = 0; i < len; i++) {
    if (buf[i] < 0x10) {
      Serial.print("0");
    }
    Serial.print(buf[i], HEX);
    if (i != len - 1) {
      Serial.print(",");
    }
  }
  Serial.println();
}
#elif
static void debug_dump(const char *msg, const uint8_t *buf = nullptr,
                       int len = 0) {);
#endif

static void get_qr_code_string(char *dst, uint16_t vid, uint16_t pid,
                               uint16_t discriminator, uint32_t pass) {
  const uint8_t version = 0;
  const uint8_t custom_flow = 0;
  const uint8_t discovery_cap = 1;  // BLE
  uint8_t buf[12];
  buf[0] = version | (vid << 3);
  buf[1] = vid >> 5;
  buf[2] = (vid >> 13) | ((pid << 3) & 0xff);
  buf[3] = pid >> 5;
  buf[4] = (pid >> 13) | (custom_flow << 3) | ((discovery_cap << 5) & 0xff);
  buf[5] = (discovery_cap >> 3) | ((discriminator << 5) & 0xff);
  buf[6] = discriminator >> 3;
  buf[7] = (discriminator >> 11) | ((pass << 1) & 0xff);
  buf[8] = pass >> 7;
  buf[9] = pass >> 15;
  buf[10] = pass >> 23;
  buf[11] = 0;
  dst[0] = 'M';
  dst[1] = 'T';
  dst[2] = ':';
  int p = 3;
  const char *b38chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-.";
  for (int i = 0; i < sizeof(buf); i += 3) {
    uint32_t d = buf[i] | (buf[i + 1] << 8) | (buf[i + 2] << 16);
    for (int j = 0; j < 5; j++) {
      dst[p++] = b38chars[d % 38];
      d /= 38;
    }
  }
  dst[p-1] = 0;
}
