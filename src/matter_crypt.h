#include <stddef.h>
#include <stdint.h>

// TODO
#if 1
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

const uint8_t spake2p_M[] = {
    0x04, 0x88, 0x6e, 0x2f, 0x97, 0xac, 0xe4, 0x6e, 0x55, 0xba, 0x9d,
    0xd7, 0x24, 0x25, 0x79, 0xf2, 0x99, 0x3b, 0x64, 0xe1, 0x6e, 0xf3,
    0xdc, 0xab, 0x95, 0xaf, 0xd4, 0x97, 0x33, 0x3d, 0x8f, 0xa1, 0x2f,
    0x5f, 0xf3, 0x55, 0x16, 0x3e, 0x43, 0xce, 0x22, 0x4e, 0x0b, 0x0e,
    0x65, 0xff, 0x02, 0xac, 0x8e, 0x5c, 0x7b, 0xe0, 0x94, 0x19, 0xc7,
    0x85, 0xe0, 0xca, 0x54, 0x7d, 0x55, 0xa1, 0x2e, 0x2d, 0x20,
};
const uint8_t spake2p_N[] = {
    0x04, 0xd8, 0xbb, 0xd6, 0xc6, 0x39, 0xc6, 0x29, 0x37, 0xb0, 0x4d,
    0x99, 0x7f, 0x38, 0xc3, 0x77, 0x07, 0x19, 0xc6, 0x29, 0xd7, 0x01,
    0x4d, 0x49, 0xa2, 0x4b, 0x4f, 0x98, 0xba, 0xa1, 0x29, 0x2b, 0x49,
    0x07, 0xd6, 0x0a, 0xa6, 0xbf, 0xad, 0xe4, 0x50, 0x08, 0xa6, 0x36,
    0x33, 0x7f, 0x51, 0x68, 0xc6, 0x4d, 0x9b, 0xd3, 0x60, 0x34, 0x80,
    0x8c, 0xd5, 0x64, 0x49, 0x0b, 0x1e, 0x65, 0x6e, 0xdb, 0xe7,
};

void hmac_sha26(const uint8_t *key, size_t key_len, const uint8_t *data,
                size_t data_len, uint8_t *out);

void pbkdf2_sha256_hmac(const uint8_t *password, size_t plen,
                        const uint8_t *salt, size_t salt_len,
                        unsigned int iteration_count, uint32_t key_len,
                        uint8_t *out);

int aes_ccm_encrypt(const uint8_t *data, size_t data_len, const uint8_t *aad,
                    size_t aad_len, const uint8_t *key128, uint8_t *tag,
                    size_t tag_len, const uint8_t *nonce, size_t nonce_len,
                    uint8_t *result);

int aes_ccm_decrypt(const uint8_t *data, size_t data_len, const uint8_t *aad,
                    size_t aad_len, const uint8_t *key128, const uint8_t *tag,
                    size_t tag_len, const uint8_t *nonce, size_t nonce_len,
                    uint8_t *result);

void ecdsa_sign(const uint8_t *msg, size_t msg_len, uint8_t *sign,
                const uint8_t *pkey);

void create_csr(const uint8_t *privkey, const uint8_t *pubkey, uint8_t *csr,
                size_t *csr_len);

void spake2p_round02(struct SHA256 *hash, const uint8_t *ws, size_t ws_len,
                     const uint8_t *pA, size_t pA_len, uint8_t *pB,
                     size_t *pB_len, uint8_t *ckey, size_t ckey_len,
                     uint8_t *skey, size_t skey_len);
