#include <string.h>

#include "../src/matter_config.h"
#include "../src/matter_esp32_crypt.h"

void testSPAKE2p() {
  SHA256 tthash;
  {
    const char* str =
        "SPAKE2+-P256-SHA256-HKDF-SHA256-HMAC-SHA256 Test Vectors";
    tthash.updateBlock((uint8_t*)str, strlen(str));
    str = "client";
    tthash.updateBlock((uint8_t*)str, strlen(str));
    str = "server";
    tthash.updateBlock((uint8_t*)str, strlen(str));
  }

  uint8_t ws[64] = {0xbb, 0x8e, 0x1b, 0xbc, 0xf3, 0xc4, 0x8f, 0x62, 0xc0, 0x8d,
                    0xb2, 0x43, 0x65, 0x2a, 0xe5, 0x5d, 0x3e, 0x55, 0x86, 0x05,
                    0x3f, 0xca, 0x77, 0x10, 0x29, 0x94, 0xf2, 0x3a, 0xd9, 0x54,
                    0x91, 0xb3, 0x7e, 0x94, 0x5f, 0x34, 0xd7, 0x87, 0x85, 0xb8,
                    0xa3, 0xef, 0x44, 0xd0, 0xdf, 0x5a, 0x1a, 0x97, 0xd6, 0xb3,
                    0xb4, 0x60, 0x40, 0x9a, 0x34, 0x5c, 0xa7, 0x83, 0x03, 0x87,
                    0xa7, 0x4b, 0x1d, 0xba};
  uint8_t pA[65] = {0x04, 0xef, 0x3b, 0xd0, 0x51, 0xbf, 0x78, 0xa2, 0x23, 0x4e,
                    0xc0, 0xdf, 0x19, 0x7f, 0x78, 0x28, 0x06, 0x0f, 0xe9, 0x85,
                    0x65, 0x03, 0x57, 0x9b, 0xb1, 0x73, 0x30, 0x09, 0x04, 0x2c,
                    0x15, 0xc0, 0xc1, 0xde, 0x12, 0x77, 0x27, 0xf4, 0x18, 0xb5,
                    0x96, 0x6a, 0xfa, 0xdf, 0xdd, 0x95, 0xa6, 0xe4, 0x59, 0x1d,
                    0x17, 0x10, 0x56, 0xb3, 0x33, 0xda, 0xb9, 0x7a, 0x79, 0xc7,
                    0x19, 0x3e, 0x34, 0x17, 0x27};
  uint8_t pB[65] = {0x04, 0xc0, 0xf6, 0x5d, 0xa0, 0xd1, 0x19, 0x27, 0xbd, 0xf5,
                    0xd5, 0x60, 0xc6, 0x9e, 0x1d, 0x7d, 0x93, 0x9a, 0x05, 0xb0,
                    0xe8, 0x82, 0x91, 0x88, 0x7d, 0x67, 0x9f, 0xca, 0xde, 0xa7,
                    0x58, 0x10, 0xfb, 0x5c, 0xc1, 0xca, 0x74, 0x94, 0xdb, 0x39,
                    0xe8, 0x2f, 0xf2, 0xf5, 0x06, 0x65, 0x25, 0x5d, 0x76, 0x17,
                    0x3e, 0x09, 0x98, 0x6a, 0xb4, 0x67, 0x42, 0xc7, 0x98, 0xa9,
                    0xa6, 0x84, 0x37, 0xb0, 0x48};
  uint8_t cB[32];
  size_t pB_len = 65, cB_len = 32, pA_len = 65;
  spake2p_round02(&tthash, ws, 64, pA, pA_len, pB, &pB_len, cB, &cB_len);
}

void testSPAKE2p_draft01() {
  SHA256 tthash;
  {
    const char* str = "SPAKE2+-P256-SHA256-HKDF draft-01";
    tthash.updateBlock((uint8_t*)str, strlen(str));
    str = "client";
    tthash.updateBlock((uint8_t*)str, strlen(str));
    str = "server";
    tthash.updateBlock((uint8_t*)str, strlen(str));
  }

  uint8_t ws[64] = {0xe6, 0x88, 0x7c, 0xf9, 0xbd, 0xfb, 0x75, 0x79, 0xc6, 0x9b,
                    0xf4, 0x79, 0x28, 0xa8, 0x45, 0x14, 0xb5, 0xe3, 0x55, 0xac,
                    0x03, 0x48, 0x63, 0xf7, 0xff, 0xaf, 0x43, 0x90, 0xe6, 0x7d,
                    0x79, 0x8c, 0x24, 0xb5, 0xae, 0x4a, 0xbd, 0xa8, 0x68, 0xec,
                    0x93, 0x36, 0xff, 0xc3, 0xb7, 0x8e, 0xe3, 0x1c, 0x57, 0x55,
                    0xbe, 0xf1, 0x75, 0x92, 0x27, 0xef, 0x53, 0x72, 0xca, 0x13,
                    0x9b, 0x94, 0xe5, 0x12};
  uint8_t pA[65] = {0x04, 0xaf, 0x09, 0x98, 0x7a, 0x59, 0x3d, 0x3b, 0xac, 0x86,
                    0x94, 0xb1, 0x23, 0x83, 0x94, 0x22, 0xc3, 0xcc, 0x87, 0xe3,
                    0x7d, 0x6b, 0x41, 0xc1, 0xd6, 0x30, 0xf0, 0x00, 0xdd, 0x64,
                    0x98, 0x0e, 0x53, 0x7a, 0xe7, 0x04, 0xbc, 0xed, 0xe0, 0x4e,
                    0xa3, 0xbe, 0xc9, 0xb7, 0x47, 0x5b, 0x32, 0xfa, 0x2c, 0xa3,
                    0xb6, 0x84, 0xbe, 0x14, 0xd1, 0x16, 0x45, 0xe3, 0x8e, 0xa6,
                    0x60, 0x9e, 0xb3, 0x9e, 0x7e};
  uint8_t pB[65] = {0x04, 0x41, 0x75, 0x92, 0x62, 0x0a, 0xeb, 0xf9, 0xfd, 0x20,
                    0x36, 0x16, 0xbb, 0xb9, 0xf1, 0x21, 0xb7, 0x30, 0xc2, 0x58,
                    0xb2, 0x86, 0xf8, 0x90, 0xc5, 0xf1, 0x9f, 0xea, 0x83, 0x3a,
                    0x9c, 0x90, 0x0c, 0xbe, 0x90, 0x57, 0xbc, 0x54, 0x9a, 0x3e,
                    0x19, 0x97, 0x5b, 0xe9, 0x92, 0x7f, 0x0e, 0x76, 0x14, 0xf0,
                    0x8d, 0x1f, 0x0a, 0x10, 0x8e, 0xed, 0xe5, 0xfd, 0x7e, 0xb5,
                    0x62, 0x45, 0x84, 0xa4, 0xf4};
  uint8_t cB[32];
  size_t pB_len = 65, cB_len = 32, pA_len = 65;
  spake2p_round02(&tthash, ws, 64, pA, pA_len, pB, &pB_len, cB, &cB_len);
}
