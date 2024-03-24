#include <mbedtls/sha256.h>

#include "matter_crypt.h"

struct SHA256 {
  mbedtls_sha256_context ctx;
  SHA256() {
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);
  }
  void update(const uint8_t *buf, uint32_t len) {
    mbedtls_sha256_update(&ctx, buf, len);
  }
  void updateBlock(const uint8_t *buf, uint32_t len) {
    uint8_t dummy[4] = {0};
    mbedtls_sha256_update(&ctx, (uint8_t *)&len, 4);  // todo byte order
    mbedtls_sha256_update(&ctx, dummy, 4);
    // debug_dump("TT block", (uint8_t *)&len, 4);
    // debug_dump("TT block", buf, len);
    if (len > 0) {
      mbedtls_sha256_update(&ctx, buf, len);
    }
  }
  void finish(uint8_t *out) {
    mbedtls_sha256_finish(&ctx, out);
    mbedtls_sha256_free(&ctx);
  }
};
