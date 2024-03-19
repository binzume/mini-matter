#include <mbedtls/ecdh.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/md.h>
#include <mbedtls/pkcs5.h>
#include <mbedtls/sha256.h>

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
    // dump("TT block", (uint8_t *)&len, 4);
    // dump("TT block", buf, len);
    if (len > 0) {
      mbedtls_sha256_update(&ctx, buf, len);
    }
  }
  void finish(uint8_t *out) {
    mbedtls_sha256_finish(&ctx, out);
    mbedtls_sha256_free(&ctx);
  }
};

static void pbkdf2_sha256_hmac(const uint8_t *password, size_t plen,
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

static void hmac_sha26(const uint8_t *key, size_t key_length,
                       const uint8_t *data, size_t data_length,
                       uint8_t *out_buffer) {
  const mbedtls_md_info_t *const md =
      mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  mbedtls_md_hmac(md, key, key_length, data, data_length, out_buffer);
}

static int p256_dmmy_rng(void *c, uint8_t *out, size_t out_len) {
  for (int i = 0; i < out_len; i++) {
    out[i] = rand();
  }
  return 0;  // TODO
}

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

static void spake2p_round02(SHA256 *hash, const uint8_t *ws, size_t ws_len,
                            const uint8_t *pA, size_t pA_len, uint8_t *pB,
                            size_t *pB_len, uint8_t *cB, size_t *cB_len) {
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

  // dump("xy", (uint8_t *)xy.p, xy.n * 4);
  // dump("w0", (uint8_t *)w0.p, w0.n * 4);
  // pB
  ret = mbedtls_ecp_muladd(&curve, &pb, &xy, &curve.G, &w0, &N);
  if (ret != 0) {
    return;
  }
  mbedtls_ecp_point_write_binary(&curve, &pb, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                 pB_len, pB, *pB_len);

  dump("pA", pA, pA_len);
  dump("pB", pB, *pB_len);

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
  dump("Z", buf, sz);

  mbedtls_ecp_point_write_binary(&curve, &v, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                 (size_t *)&sz, buf, sizeof(buf));
  hash->updateBlock(buf, sz);
  dump("V", buf, sz);

  mbedtls_mpi_write_binary(&w0, buf, 32); // ws_len / 2

  hash->updateBlock(buf, 32);
  dump("w0", buf, 32);
  hash->finish(buf);

  dump("TT hash", buf, 32);
  // kca|kcb = HKDF_SHA256( tthash.fistharf , info = "ConfirmationKeys")
  // cB = HMAC(Kcb, pa = X)
  const char *info = "ConfirmationKeys";
  uint8_t buf2[32];  // draft01
  mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), nullptr, 0, buf,
               16, (const uint8_t *)info, strlen(info), buf2, sizeof(buf2));
  dump("K_confirm", buf2, sizeof(buf2));

  *cB_len = 32;
  hmac_sha26(buf2 + sizeof(buf2) / 2, sizeof(buf2) / 2, pA, pA_len, cB);

  dump("cB", cB, *cB_len);

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
