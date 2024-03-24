#include "matter_crypt_esp32.h"

#include <mbedtls/ccm.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/md.h>
#include <mbedtls/pkcs5.h>
#include <mbedtls/sha256.h>

void pbkdf2_sha256_hmac(const uint8_t *password, size_t plen,
                        const uint8_t *salt, size_t salt_len,
                        unsigned int iteration_count, uint32_t key_len,
                        uint8_t *out) {
  mbedtls_md_context_t md;
  mbedtls_md_init(&md);
  mbedtls_md_setup(&md, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
  mbedtls_pkcs5_pbkdf2_hmac(&md, password, plen, salt, salt_len,
                            iteration_count, key_len, out);
  mbedtls_md_free(&md);
}

void hmac_sha26(const uint8_t *key, size_t key_length, const uint8_t *data,
                size_t data_length, uint8_t *out_buffer) {
  const mbedtls_md_info_t *const md =
      mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  mbedtls_md_hmac(md, key, key_length, data, data_length, out_buffer);
}

int aes_ccm_decrypt(const uint8_t *data, size_t data_len, const uint8_t *aad,
                    size_t aad_len, const uint8_t *key128, const uint8_t *tag,
                    size_t tag_len, const uint8_t *nonce, size_t nonce_len,
                    uint8_t *result) {
  mbedtls_ccm_context ctx;
  mbedtls_ccm_init(&ctx);
  mbedtls_ccm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key128, 16 * 8);
  int ret = mbedtls_ccm_auth_decrypt(&ctx, data_len, nonce, nonce_len, aad,
                                     aad_len, data, result, tag, tag_len);
  mbedtls_ccm_free(&ctx);
  return ret;
}

int aes_ccm_encrypt(const uint8_t *data, size_t data_len, const uint8_t *aad,
                    size_t aad_len, const uint8_t *key128, uint8_t *tag,
                    size_t tag_len, const uint8_t *nonce, size_t nonce_len,
                    uint8_t *result) {
  mbedtls_ccm_context ctx;
  mbedtls_ccm_init(&ctx);
  mbedtls_ccm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key128, 16 * 8);
  int ret = mbedtls_ccm_encrypt_and_tag(&ctx, data_len, nonce, nonce_len, aad,
                                        aad_len, data, result, tag, tag_len);
  mbedtls_ccm_free(&ctx);
  return ret;
}

int p256_dmmy_rng(void *c, uint8_t *out, size_t out_len) {
  for (int i = 0; i < out_len; i++) {
    out[i] = rand();
  }
  return 0;  // TODO
}

void spake2p_round02(struct SHA256 *hash, const uint8_t *ws, size_t ws_len,
                     const uint8_t *pA, size_t pA_len, uint8_t *pB,
                     size_t *pB_len, uint8_t *ckey, size_t ckey_len,
                     uint8_t *skey, size_t skey_len) {
  // xy = random
  // pB = Y = xy*G + w0 * N

  mbedtls_ecp_group curve;
  mbedtls_mpi xy;
  mbedtls_mpi w0;
  mbedtls_ecp_point pb;
  mbedtls_ecp_point M;
  mbedtls_ecp_point N;

  mbedtls_ecp_group_init(&curve);
  mbedtls_mpi_init(&xy);
  mbedtls_mpi_init(&w0);
  mbedtls_ecp_point_init(&pb);
  mbedtls_ecp_point_init(&M);
  mbedtls_ecp_point_init(&N);

  int ret = mbedtls_ecp_group_load(&curve, MBEDTLS_ECP_DP_SECP256R1);
  if (ret != 0) {
    return;
  }
  ret = mbedtls_ecp_gen_privkey(&curve, &xy, p256_dmmy_rng, nullptr);
  if (ret != 0) {
    return;
  }

  /*
    {  // DBG
      const uint8_t sx[] = {0x2e, 0x08, 0x95, 0xb0, 0xe7, 0x63, 0xd6, 0xd5,
                            0xa9, 0x56, 0x44, 0x33, 0xe6, 0x4a, 0xc3, 0xca,
                            0xc7, 0x4f, 0xf8, 0x97, 0xf6, 0xc3, 0x44, 0x52,
                            0x47, 0xba, 0x1b, 0xab, 0x40, 0x08, 0x2a, 0x91};
      ret = mbedtls_mpi_read_binary(&xy, sx, sizeof(sx));
      if (ret != 0) {
        return;
      }
    }
  */

  ret = mbedtls_ecp_point_read_binary(&curve, &M, spake2p_M, sizeof(spake2p_M));
  if (ret != 0) {
    return;
  }
  ret = mbedtls_ecp_point_read_binary(&curve, &N, spake2p_N, sizeof(spake2p_N));
  if (ret != 0) {
    return;
  }

  // w0
  ret = mbedtls_mpi_read_binary(&w0, ws, ws_len / 2);
  if (ret != 0) {
    return;
  }
  ret = mbedtls_mpi_mod_mpi(&w0, &w0, &curve.N);
  if (ret != 0) {
    return;
  }

  // pB
  ret = mbedtls_ecp_muladd(&curve, &pb, &xy, &curve.G, &w0, &N);
  if (ret != 0) {
    return;
  }
  mbedtls_ecp_point_write_binary(&curve, &pb, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                 pB_len, pB, *pB_len);

  debug_dump("pA", pA, pA_len);
  debug_dump("pB", pB, *pB_len);

  // TT
  uint8_t buf[80];
  uint32_t sz = 0;

  mbedtls_ecp_point_write_binary(&curve, &M, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                 (size_t *)&sz, buf, sizeof(buf));
  hash->updateBlock(buf, sz);

  mbedtls_ecp_point_write_binary(&curve, &N, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                 (size_t *)&sz, buf, sizeof(buf));
  hash->updateBlock(buf, sz);

  sz = pA_len;
  hash->updateBlock(pA, pA_len);
  sz = *pB_len;
  hash->updateBlock(pB, *pB_len);

  // Z = cmul(xy*X + xy*w0*inv(MN))
  // V = cmul(xy * L)

  mbedtls_ecp_point z;
  mbedtls_ecp_point v;
  mbedtls_ecp_point l;
  mbedtls_ecp_point_init(&l);
  mbedtls_ecp_point_init(&z);
  mbedtls_ecp_point_init(&v);
  mbedtls_mpi w1;
  mbedtls_mpi_init(&w1);

  // Z = *xy*(X - w0*M) => xy*X + xy*w0*(-M)
  mbedtls_ecp_point x;
  mbedtls_mpi t;
  mbedtls_ecp_point_init(&x);
  mbedtls_mpi_init(&t);

  ret = mbedtls_mpi_sub_mpi(&M.Y, &curve.P, &M.Y);  // inv TODO:copy
  if (ret != 0) {
    return;
  }
  ret = mbedtls_ecp_point_read_binary(&curve, &x, pA, pA_len);
  if (ret != 0) {
    return;
  }
  ret = mbedtls_mpi_mul_mpi(&t, &xy, &w0);
  if (ret != 0) {
    return;
  }
  mbedtls_mpi_mod_mpi(&t, &t, &curve.N);
  ret = mbedtls_ecp_muladd(&curve, &z, &xy, &x, &t, &M);
  if (ret != 0) {
    return;
  }

  // L = (w1 mod N) * G
  // V = xy * L
  mbedtls_mpi_read_binary(&w1, ws + ws_len / 2, ws_len / 2);
  mbedtls_mpi_mod_mpi(&w1, &w1, &curve.N);
  mbedtls_ecp_mul(&curve, &l, &w1, &curve.G, p256_dmmy_rng, nullptr);
  mbedtls_ecp_mul(&curve, &v, &xy, &l, p256_dmmy_rng, nullptr);

  mbedtls_ecp_point_write_binary(&curve, &z, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                 (size_t *)&sz, buf, sizeof(buf));
  hash->updateBlock(buf, sz);
  debug_dump("Z", buf, sz);

  mbedtls_ecp_point_write_binary(&curve, &v, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                 (size_t *)&sz, buf, sizeof(buf));
  hash->updateBlock(buf, sz);
  debug_dump("V", buf, sz);

  mbedtls_mpi_write_binary(&w0, buf, 32);  // ws_len / 2

  hash->updateBlock(buf, 32);
  debug_dump("w0", buf, 32);
  hash->finish(buf);

  debug_dump("TT hash", buf, 32);
  if (ckey_len) {
    const char *info = "ConfirmationKeys";
    mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), nullptr, 0, buf,
                 16, (const uint8_t *)info, strlen(info), ckey, ckey_len);
    debug_dump("K_confirm", ckey, ckey_len);
  }
  if (skey_len) {
    const char *info = "SessionKeys";
    mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), nullptr, 0,
                 buf + 16, 16, (const uint8_t *)info, strlen(info), skey,
                 skey_len);
    debug_dump("keys", skey, skey_len);
  }

  // TODO: free when error case
  mbedtls_ecp_group_free(&curve);

  mbedtls_ecp_point_free(&x);

  mbedtls_mpi_free(&xy);
  mbedtls_mpi_free(&w0);
  mbedtls_mpi_free(&w1);
  mbedtls_mpi_free(&t);
  mbedtls_ecp_point_free(&pb);
  mbedtls_ecp_point_free(&z);
  mbedtls_ecp_point_free(&v);
  mbedtls_ecp_point_free(&l);
  mbedtls_ecp_point_free(&M);
  mbedtls_ecp_point_free(&N);
}
