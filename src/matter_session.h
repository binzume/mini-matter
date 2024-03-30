#include "matter_sha256_esp32.h"

#define TT_CONTEXT_INIT "CHIP PAKE V1 Commissioning"

// TODO: more secure random
#define RANDOM ((uint8_t *)"0123456789abcdefghijklmnopqrstuv")
#define SALT ((uint8_t *)"0123456789abcdef")
#define HMAC_ITER 1000

struct MatterSession {
  uint8_t recv_buf[1024];
  uint8_t send_buf[1024];
  uint16_t recv_size;
  uint16_t send_size;
  uint16_t send_pos;
  uint8_t keys[48];  // I2R[16] + R2I[16] + Challenge[16]
  uint8_t btp_tx_seq;
  uint8_t btp_rx_seq;
  uint16_t session_id;  // initiator secure session id
  uint32_t msg_count;
  SHA256 contextHash;
  int8_t network_state;
};
