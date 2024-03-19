#include "matter_config.h"
#include "matter_esp32_crypt.h"
#include "matter_protocol.h"

#define TT_CONTEXT_INIT "CHIP PAKE V1 Commissioning"

#define RANDOM ((uint8_t *)"0123456789abcdefghijklmnopqrstuv")
// #define SALT ((uint8_t *)"0123456789abcdef")
const uint8_t SALT[16] = {0x53, 0x50, 0x41, 0x4B, 0x45, 0x32, 0x50, 0x20,
                        0x4B, 0x65, 0x79, 0x20, 0x53, 0x61, 0x6C, 0x74};
#define HMAC_ITER 1000

struct PaseContext {
  SHA256 contextHash;
};

int make_handshake_res(PaseContext *ctx, const uint8_t *req, int reqsize,
                       uint8_t *res) {
  res[0] = 0b1100101;
  res[1] = 0x6C;
  res[2] = 0x04;  // ver
  res[3] = 244;   // mtu
  res[4] = 0;
  res[5] = 5;  // window
  return 6;
}

int make_pbdkres(PaseContext *ctx, const uint8_t *req, int reqsize,
                 uint8_t *res) {
  const uint8_t *initiatorRandom = RANDOM;

  ctx->contextHash.update((uint8_t *)TT_CONTEXT_INIT, strlen(TT_CONTEXT_INIT));

  int pos = 0;
  pos += btp_get_header_size(req);
  uint64_t sender = message_get_sender(req + pos);
  pos += message_get_header_size(req + pos);
  uint16_t exchangeId = message_get_proto_echange_id(req + pos);
  pos += message_get_pheader_size(req + pos);
  ctx->contextHash.update(&req[pos], reqsize - pos);

  while (pos < reqsize) {
    tag_info ti;
    pos += tlv_read_tag(req + pos, &ti);
    if (ti.tag == 1 && ti.data_ref) {
      initiatorRandom = ti.data_ref;
    }
  }

  // PBKDFParamResponse
  int l = 0;
  l += btp_write_header(res + l, 0, 1, 0);  // ack, seq, sz(dummy)
  l += message_write_header(res + l, 0, 1, sender);
  l += message_write_pheader(res + l, MSG_PROTO_OP_PBKD_RES, exchangeId,
                             MSG_PROTO_ID_SECURE, 0);
  pos = l;
  l += tlv_write_struct(res + l, 0, 0);  // pbkdfparamresp-struct
  l += tlv_write_str(res + l, 1, 1, initiatorRandom, 32);  // initiatorRandom
  l += tlv_write_str(res + l, 1, 2, RANDOM, 32);           // responderRandom
  l += tlv_write(res + l, 1, 3, (uint16_t)1);              // responderSessionId
  l += tlv_write_struct(res + l, 1, 4);                    // pbkdf_parameters
  l += tlv_write(res + l, 1, 1, (uint16_t)HMAC_ITER);      // iterations
  l += tlv_write_str(res + l, 1, 2, SALT, 16);             // salt
  l += tlv_write_eos(res + l);  // end of pbkdf_parameters
  l += tlv_write_eos(res + l);
  btp_update_size(res, l - 5);  // update payload size

  ctx->contextHash.update(&res[pos], l - pos);

  return l;
}

int make_pake2(PaseContext *ctx, const uint8_t *req, int reqsize,
               uint8_t *res) {
  int pos = 0;
  pos += btp_get_header_size(req);
  uint64_t sender = message_get_sender(req + pos);
  pos += message_get_header_size(req + pos);
  uint16_t exchangeId = message_get_proto_echange_id(req + pos);
  pos += message_get_pheader_size(req + pos);

  const uint8_t *pA = nullptr;
  int pA_len = 0;
  while (pos < reqsize) {
    tag_info ti;
    pos += tlv_read_tag(req + pos, &ti);
    if (ti.tag == 1 && ti.data_ref) {
      pA = ti.data_ref;
      pA_len = ti.val_or_len;
    }
  }

  SHA256 tthash;
  {
    uint8_t ttctx[32];
    ctx->contextHash.finish(ttctx);
    dump("CtxHash", ttctx, sizeof(ttctx));
    tthash.updateBlock(ttctx, sizeof(ttctx));
    tthash.updateBlock(nullptr, 0);
    tthash.updateBlock(nullptr, 0);
  }

  uint8_t ws[80];
  {
    uint32_t pin = PIN;
    pbkdf2_sha256_hmac((const uint8_t *)&pin, 4, SALT, 16, HMAC_ITER,
                       sizeof(ws), ws);
  }

  uint8_t cB[32], pB[65];
  size_t pB_len = 65, cB_len = 32;
  spake2p_round02(&tthash, ws, sizeof(ws), pA, pA_len, pB, &pB_len, cB,
                  &cB_len);

  int l = 0;
  l += btp_write_header(res + l, 1, 2, 0);  // ack, seq, sz(dummy)
  l += message_write_header(res + l, 0, 2, sender);
  l += message_write_pheader(res + l, MSG_PROTO_OP_PASE_PAKE2, exchangeId,
                             MSG_PROTO_ID_SECURE, 0);
  l += tlv_write_struct(res + l, 0, 0);           // pbkdfparamresp-struct
  l += tlv_write_str(res + l, 1, 1, pB, pB_len);  // pB
  l += tlv_write_str(res + l, 1, 2, cB, cB_len);  // cB
  l += tlv_write_eos(res + l);
  btp_update_size(res, l - 5);  // update payload size
  return l;
}
