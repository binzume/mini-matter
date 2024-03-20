#include "matter_pase.h"

#include "matter_config.h"
#include "matter_protocol.h"

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

#include "matter_esp32_crypt.h"

#define TT_CONTEXT_INIT "CHIP PAKE V1 Commissioning"

#define RANDOM ((uint8_t *)"0123456789abcdefghijklmnopqrstuv")
// #define SALT ((uint8_t *)"0123456789abcdef")
const uint8_t SALT[16] = {0x53, 0x50, 0x41, 0x4B, 0x45, 0x32, 0x50, 0x20,
                          0x4B, 0x65, 0x79, 0x20, 0x53, 0x61, 0x6C, 0x74};
#define HMAC_ITER 1000

struct PaseContext {
  int count;
  SHA256 contextHash;
};

int handle_btp_handshake(PaseContext *ctx, const uint8_t *req, int reqsize,
                         uint8_t *res) {
  res[0] = 0b1100101;
  res[1] = 0x6C;
  res[2] = 0x04;  // ver
  res[3] = 244;   // mtu
  res[4] = 0;
  res[5] = 5;  // window
  return 6;
}

int handle_pbdkreq(PaseContext *ctx, const uint8_t *req, int reqsize,
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

int handle_pake1(PaseContext *ctx, const uint8_t *req, int reqsize,
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
    debug_dump("CtxHash", ttctx, sizeof(ttctx));
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

  uint8_t cB[32], pB[65], ck[32];
  size_t pB_len = 65;
  spake2p_round02(&tthash, ws, sizeof(ws), pA, pA_len, pB, &pB_len, ck, 32);

  hmac_sha26(ck + sizeof(ck) / 2, sizeof(ck) / 2, pA, pA_len, cB);
  debug_dump("cB", cB, sizeof(cB));

  {
    uint8_t cA[32];
    hmac_sha26(ck, sizeof(ck) / 2, pB, pB_len, cA);
    debug_dump("cA(expected)", cA, sizeof(cA));
  }

  int l = 0;
  l += btp_write_header(res + l, 1, 2, 0);  // ack, seq, sz(dummy)
  l += message_write_header(res + l, 0, 2, sender);
  l += message_write_pheader(res + l, MSG_PROTO_OP_PASE_PAKE2, exchangeId,
                             MSG_PROTO_ID_SECURE, 0);
  l += tlv_write_struct(res + l, 0, 0);               // pbkdfparamresp-struct
  l += tlv_write_str(res + l, 1, 1, pB, pB_len);      // pB
  l += tlv_write_str(res + l, 1, 2, cB, sizeof(cB));  // cB
  l += tlv_write_eos(res + l);
  btp_update_size(res, l - 5);  // update payload size
  return l;
}

int handle_pake3(PaseContext *ctx, const uint8_t *req, int reqsize,
                 uint8_t *res) {
  int pos = 0;
  pos += btp_get_header_size(req);
  uint64_t sender = message_get_sender(req + pos);
  pos += message_get_header_size(req + pos);
  uint16_t exchangeId = message_get_proto_echange_id(req + pos);
  pos += message_get_pheader_size(req + pos);

  const uint8_t *cA = nullptr;
  int cA_len = 0;
  while (pos < reqsize) {
    tag_info ti;
    pos += tlv_read_tag(req + pos, &ti);
    if (ti.tag == 1 && ti.data_ref) {
      cA = ti.data_ref;
      cA_len = ti.val_or_len;
    }
  }
  debug_dump("cA", cA, cA_len);

  int l = btp_write_header(res, 2, 3, 0);  // ack, seq, sz(dummy)
  l += message_write_header(res + l, 0, 3, sender);
  l += message_write_pheader(res + l, MSG_PROTO_OP_STATUS_REPORT, exchangeId,
                             MSG_PROTO_ID_SECURE, 0);
  l += write_status_report(res + l, MSG_STATUS_REPORT_SUCCESS,
                           MSG_STATUS_REPORT_SESSION_ESTABLISHMENT_SUCCESS);

  btp_update_size(res, l - 5);  // update payload size
  return l;
}

PaseContext *pase_init() {
  PaseContext *ctx = new PaseContext();
  ctx->count = 0;
  return ctx;
}

int handle_btp_packet(PaseContext *ctx, const uint8_t *req, int reqsize,
                      uint8_t *res) {
  if (reqsize < 6) {
    return 0;
  }
  ctx->count++;
  if (req[0] == 0x65) {
    ctx->count = 1;
    return handle_btp_handshake(ctx, req, reqsize, res);
  } else if (ctx->count == 2) {
    return handle_pbdkreq(ctx, req, reqsize, res);
  } else if (ctx->count == 3) {
    return handle_pake1(ctx, req, reqsize, res);
  } else if (ctx->count == 4) {
    return handle_pake3(ctx, req, reqsize, res);
  }
  return 0;
}
