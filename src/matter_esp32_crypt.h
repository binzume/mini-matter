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
  void finish(uint8_t *out) { mbedtls_sha256_finish(&ctx, out); }
  ~SHA256() { mbedtls_sha256_free(&ctx); }
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

static void p256_point_mod_N(const uint8_t *in, size_t in_len, uint8_t *out,
                             size_t out_len) {
  mbedtls_ecp_group curve;
  mbedtls_mpi t;
  mbedtls_ecp_group_init(&curve);
  mbedtls_mpi_init(&t);
  mbedtls_ecp_group_load(&curve, MBEDTLS_ECP_DP_SECP256R1);

  mbedtls_mpi_read_binary(&t, in, in_len);
  mbedtls_mpi_mod_mpi(&t, &t, &curve.N);
  mbedtls_mpi_write_binary(&t, out, out_len);

  mbedtls_ecp_group_free(&curve);
  mbedtls_mpi_free(&t);
}

static int p256_dmmy_rng(void *c, uint8_t *out, size_t out_len) {
  return 0;  // TODO
}

static void p256_point_mod_N_mul_G(const uint8_t *win, size_t win_len,
                                   uint8_t *out, size_t *out_len) {
  mbedtls_ecp_group curve;
  mbedtls_mpi w_bn;
  mbedtls_ecp_point t;
  mbedtls_ecp_group_init(&curve);
  mbedtls_mpi_init(&w_bn);
  mbedtls_ecp_point_init(&t);

  mbedtls_ecp_group_load(&curve, MBEDTLS_ECP_DP_SECP256R1);
  mbedtls_mpi_read_binary(&w_bn, win, win_len);
  mbedtls_mpi_mod_mpi(&w_bn, &w_bn, &curve.N);
  mbedtls_ecp_mul(&curve, &t, &w_bn, &curve.G, p256_dmmy_rng, nullptr);

  mbedtls_ecp_point_write_binary(&curve, &t, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                 out_len, out, *out_len);
  mbedtls_ecp_point_free(&t);
  mbedtls_mpi_free(&w_bn);
  mbedtls_ecp_group_free(&curve);
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

static void debug_calc_cb(SHA256 *hash, const uint8_t *ws, const uint8_t *pA,
                          size_t pA_len, uint8_t *pB, size_t *pBlen,
                          uint8_t *cB, size_t *cBlen) {
  // xy = random
  // pB = Y = xy*G + w0 * N

  mbedtls_ecp_group curve;
  mbedtls_mpi xy;
  mbedtls_mpi w0;
  mbedtls_mpi w1;
  mbedtls_mpi t;
  mbedtls_ecp_point pb;
  mbedtls_ecp_point M;
  mbedtls_ecp_point N;
  mbedtls_ecp_point z;
  mbedtls_ecp_point v;
  mbedtls_ecp_point l;

  mbedtls_ecp_group_init(&curve);
  mbedtls_mpi_init(&xy);
  mbedtls_mpi_init(&w0);
  mbedtls_mpi_init(&w1);
  mbedtls_mpi_init(&t);
  mbedtls_ecp_point_init(&pb);
  mbedtls_ecp_point_init(&z);
  mbedtls_ecp_point_init(&v);
  mbedtls_ecp_point_init(&l);
  mbedtls_ecp_point_init(&M);
  mbedtls_ecp_point_init(&N);

  mbedtls_ecp_gen_privkey(&curve, &xy, p256_dmmy_rng, nullptr);

  mbedtls_ecp_point_read_binary(&curve, &M, spake2p_M, sizeof(spake2p_M));
  mbedtls_ecp_point_read_binary(&curve, &M, spake2p_N, sizeof(spake2p_N));

  // w0
  mbedtls_mpi_read_binary(&w0, ws, 40);
  mbedtls_mpi_mod_mpi(&w0, &w0, &curve.N);

  // pB
  mbedtls_ecp_muladd(&curve, &pb, &xy, &curve.G, &w0, &N);
  mbedtls_mpi_sub_mpi(&pb.Y, &curve.P, &pb.Y);  // inv
  mbedtls_ecp_point_write_binary(&curve, &pb, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                 pBlen, pB, 65);

  dump("pb", pB, *pBlen);

  // Z = cmul(xy*X + xy*w0*inv(MN))
  // V = cmul(xy * L)

  // Z
  mbedtls_ecp_point x;
  mbedtls_ecp_point m;
  mbedtls_ecp_point_init(&x);
  mbedtls_ecp_point_init(&m);

  mbedtls_mpi_sub_mpi(&M.Y, &curve.P, &M.Y);  // inv TODO:copy
  mbedtls_ecp_point_read_binary(&curve, &x, pA, 65);
  mbedtls_mpi_mul_mpi(&t, &xy, &w0);
  mbedtls_ecp_muladd(&curve, &z, &xy, &x, &t, &m);

  // L = (w1 mod N) * G
  // V = xy * L
  mbedtls_mpi_read_binary(&w1, ws + 40, 40);
  mbedtls_mpi_mod_mpi(&w1, &w1, &curve.N);
  mbedtls_ecp_mul(&curve, &l, &w1, &curve.G, p256_dmmy_rng, nullptr);
  mbedtls_ecp_mul(&curve, &v, &xy, &l, p256_dmmy_rng, nullptr);

  // TT
  uint8_t buf[80];

  uint64_t sz = 0;
  hash->update((uint8_t *)&sz, 8);
  hash->update((uint8_t *)&sz, 8);

  mbedtls_ecp_point_write_binary(&curve, &M, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                 (size_t *)&sz, buf, sizeof(buf));
  hash->update((uint8_t *)&sz, 8);
  hash->update(buf, sz);

  mbedtls_ecp_point_write_binary(&curve, &N, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                 (size_t *)&sz, buf, sizeof(buf));
  hash->update((uint8_t *)&sz, 8);
  hash->update(buf, sz);

  sz = pA_len;
  hash->update((uint8_t *)&sz, 8);
  hash->update(pA, pA_len);
  sz = *pBlen;
  hash->update((uint8_t *)&sz, 8);
  hash->update(pB, *pBlen);

  mbedtls_ecp_point_write_binary(&curve, &z, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                 (size_t *)&sz, buf, sizeof(buf));
  hash->update((uint8_t *)&sz, 8);
  hash->update(buf, sz);

  mbedtls_ecp_point_write_binary(&curve, &v, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                 (size_t *)&sz, buf, sizeof(buf));
  hash->update((uint8_t *)&sz, 8);
  hash->update(buf, sz);

  sz = 40;
  mbedtls_mpi_write_binary(&w0, buf, 40);
  hash->update((uint8_t *)&sz, 8);
  hash->update(buf, sz);
  hash->finish(buf);

  dump("TT hash:", buf, 32);

  // kca|kcb = HKDF_SHA256( tthash.fistharf , info = "ConfirmationKeys")
  // cB = HMAC(Kcb, pa = X)
  const char *info = "ConfirmationKeys";
  uint8_t buf2[32];
  mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), nullptr, 0, buf,
               16, (const uint8_t *)info, strlen(info) - 1, buf2, 32);

  *cBlen = 32;
  hmac_sha26(buf2 + 16, 16, pA, pA_len, cB);

  dump("cB:", cB, *cBlen);

  mbedtls_ecp_group_free(&curve);

  mbedtls_ecp_point_free(&x);
  mbedtls_ecp_point_free(&m);

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
