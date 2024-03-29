#include "matter_pase.h"

#include "matter_config.h"
#include "matter_crypt_esp32.h"
#include "matter_protocol.h"

#define TT_CONTEXT_INIT "CHIP PAKE V1 Commissioning"

// TODO: more secure random
#define RANDOM ((uint8_t *)"0123456789abcdefghijklmnopqrstuv")
#define SALT ((uint8_t *)"0123456789abcdef")
#define HMAC_ITER 1000

struct PaseContext {
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
};

PaseContext *pase_init() {
  PaseContext *ctx = new PaseContext();
  ctx->recv_size = 0;
  ctx->send_size = 0;
  ctx->send_pos = 0;
  ctx->msg_count = 0;
  ctx->btp_tx_seq = 0;
  return ctx;
}

int handle_btp_handshake(PaseContext *ctx, const uint8_t *req, size_t reqsize,
                         uint8_t *res) {
  res[0] = 0b1100101;
  res[1] = 0x6C;
  res[2] = 0x04;  // ver
  res[3] = 244;   // mtu
  res[4] = 0;
  res[5] = 5;  // window
  return 6;
}

int handle_pbdkreq(PaseContext *ctx, const uint8_t *req, size_t reqsize,
                   uint8_t *res) {
  const uint8_t *initiatorRandom = nullptr;

  ctx->contextHash.update((uint8_t *)TT_CONTEXT_INIT, strlen(TT_CONTEXT_INIT));

  int pos = 0;
  uint64_t sender = message_get_sender(req + pos);
  pos += message_get_header_size(req + pos);
  uint16_t exchangeId = message_get_proto_echange_id(req + pos);
  pos += message_get_pheader_size(req + pos);
  ctx->contextHash.update(&req[pos], reqsize - pos);

  ctx->session_id = 0;
  while (pos < reqsize) {
    tag_info ti;
    pos += tlv_read_tag(req + pos, &ti);
    if (ti.tag == 1 && ti.data_ref) {
      initiatorRandom = ti.data_ref;
    }
    if (ti.tag == 2 && ctx->session_id == 0) {
      ctx->session_id = ti.val_or_len;
    }
  }
  if (initiatorRandom == nullptr) {
    return 0;
  }

  // PBKDFParamResponse
  int l = 0;
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

  ctx->contextHash.update(&res[pos], l - pos);

  return l;
}

int handle_pake1(PaseContext *ctx, const uint8_t *req, size_t reqsize,
                 uint8_t *res) {
  int pos = 0;
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
  if (pA == nullptr) {
    return 0;
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
  spake2p_round02(&tthash, ws, sizeof(ws), pA, pA_len, pB, &pB_len, ck,
                  sizeof(ck), ctx->keys, sizeof(ctx->keys));

  hmac_sha26(ck + sizeof(ck) / 2, sizeof(ck) / 2, pA, pA_len, cB);
  debug_dump("cB", cB, sizeof(cB));

  {
    uint8_t cA[32];
    hmac_sha26(ck, sizeof(ck) / 2, pB, pB_len, cA);
    debug_dump("cA(expected)", cA, sizeof(cA));
  }

  int l = 0;
  l += message_write_header(res + l, 0, 2, sender);
  l += message_write_pheader(res + l, MSG_PROTO_OP_PASE_PAKE2, exchangeId,
                             MSG_PROTO_ID_SECURE, 0);
  l += tlv_write_struct(res + l, 0, 0);               // pbkdfparamresp-struct
  l += tlv_write_str(res + l, 1, 1, pB, pB_len);      // pB
  l += tlv_write_str(res + l, 1, 2, cB, sizeof(cB));  // cB
  l += tlv_write_eos(res + l);
  return l;
}

int handle_pake3(PaseContext *ctx, const uint8_t *req, size_t reqsize,
                 uint8_t *res) {
  uint64_t sender = message_get_sender(req);
  int pos = message_get_header_size(req);
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

  int l = 0;
  l += message_write_header(res + l, 0, 3, sender);
  l += message_write_pheader(res + l, MSG_PROTO_OP_STATUS_REPORT, exchangeId,
                             MSG_PROTO_ID_SECURE, 0);
  l += write_status_report(res + l, MSG_STATUS_REPORT_SUCCESS,
                           MSG_STATUS_REPORT_SESSION_ESTABLISHMENT_SUCCESS);
  return l;
}

void get_nonce(const uint8_t *msg, uint8_t *nonce) {
  nonce[0] = msg[3];
  nonce[1] = msg[4];
  nonce[2] = msg[5];
  nonce[3] = msg[6];
  nonce[4] = msg[7];
  // TODO: sender id
}

int encrypt_message(PaseContext *ctx, const uint8_t *msg, size_t msg_len,
                    uint8_t *buf) {
  int header_len = message_get_header_size(msg);
  int data_len = msg_len - header_len;
  if (data_len <= 0) {
    // debug_dump("nodata");
    return msg_len;
  }
  uint8_t nonce[13] = {0};
  get_nonce(msg, nonce);
  // debug_dump("encrypt", msg + header_len, data_len);
  aes_ccm_encrypt(msg + header_len, data_len, msg, header_len, ctx->keys + 16,
                  buf + msg_len - header_len, 16, nonce, sizeof(nonce), buf);

  // debug_dump("encrypted", msg + header_len, data_len + 16);
  return msg_len + 16;
}

int decrypt_message(PaseContext *ctx, const uint8_t *msg, size_t msg_len,
                    uint8_t *buf) {
  int header_len = message_get_header_size(msg);
  int data_len = msg_len - header_len - 16;
  if (data_len <= 0) {
    // debug_dump("nodata");
    return 0;
  }
  uint8_t nonce[13] = {0};
  get_nonce(msg, nonce);
  // debug_dump("decrypt", msg + header_len, data_len);
  aes_ccm_decrypt(msg + header_len, data_len, msg, header_len, ctx->keys,
                  msg + msg_len - 16, 16, nonce, sizeof(nonce), buf);
  debug_dump("decrypted", buf, data_len);
  return data_len;
}

int handle_read_report(PaseContext *ctx, const uint8_t *req, size_t reqsize,
                       uint8_t *res) {
  uint8_t endpoint = 0x00;
  uint8_t cluster = 0;     // Descriptor
  uint16_t attribute = 0;  // ServerList
  // 0x1d/0x01 Descriptor/ServerList
  // 0x28/0x02 Basic Information/VendorID
  // 0x3E/0x02 Operational Credentials/SupportedFabrics

  int pos = 0;
  while (pos < reqsize) {
    tag_info ti;
    pos += tlv_read_tag(req + pos, &ti);
    if (ti.tag == 3 && cluster == 0) {
      cluster = ti.val_or_len;
    }
    if (ti.tag == 4 && attribute == 0) {
      attribute = ti.val_or_len;
    }
  }

  int l = 0;
  // ReportDataMessage
  l += tlv_write_struct(res + l, 0, 0);
  {
    // AttributeReports
    l += tlv_write_array(res + l, 1, 1);
    {
      // AttributeReportIB
      l += tlv_write_struct(res + l, 0, 0);
      /*
            // AttributeStatus
            l += tlv_write_struct(res + l, 1, 0);
            {
              // Path
              l += tlv_write_list(res + l, 1, 0);
              l += tlv_write(res + l, 1, 2, endpoint);
              l += tlv_write(res + l, 1, 3, cluster);
              l += tlv_write(res + l, 1, 4, attribute);
              l += tlv_write_eos(res + l);

              // Status
              l += tlv_write_struct(res + l, 1, 1);
              l += tlv_write(res + l, 1, 0, (uint8_t)0);  // Status
              l += tlv_write(res + l, 1, 1, (uint8_t)0);  // ClusterStatus
              l += tlv_write_eos(res + l);
            }
            l += tlv_write_eos(res + l);  // End AttributeStatus
      */
      // AttributeData
      l += tlv_write_struct(res + l, 1, 1);
      {
        // Version
        l += tlv_write(res + l, 1, 0, (uint16_t)1);

        // Path
        l += tlv_write_list(res + l, 1, 1);
        l += tlv_write(res + l, 1, 2, endpoint);
        l += tlv_write(res + l, 1, 3, cluster);
        l += tlv_write(res + l, 1, 4, attribute);
        l += tlv_write_eos(res + l);

        // Data
        if (cluster == 0x1d && attribute == 0x01) {
          l += tlv_write_array(res + l, 1, 2);
          l += tlv_write(res + l, 0, 0, (uint16_t)0x1d);
          l += tlv_write(res + l, 0, 0,
                         (uint16_t)0x31);  // Network Commissioning
          l += tlv_write(res + l, 0, 0, (uint16_t)0x3456);
          l += tlv_write_eos(res + l);
        } else if (cluster == 0x28 && attribute == 0x02) {
          l += tlv_write(res + l, 1, 2, (uint16_t)BLE_VENDOR_ID);
        } else if (cluster == 0x28 && attribute == 0x04) {
          l += tlv_write(res + l, 1, 2, (uint16_t)BLE_PRODUCT_ID);
        } else if (cluster == 0x30 && attribute == 0x03) {
          // LocationCapability = 2(IndoorOutdoor)
          l += tlv_write(res + l, 1, 2, (uint8_t)0x02);
        } else if (cluster == 0x31 && attribute == 0xfffc) {
          // FeatureMap
          l += tlv_write(res + l, 1, 2, (uint32_t)1);  // WiFi
        } else if (cluster == 0x31 && attribute == 0x03) {
          // ConnectMaxTimeSeconds
          l += tlv_write(res + l, 1, 2, (uint8_t)30);
        } else if (cluster == 0x3e && attribute == 0x01) {
          l += tlv_write_array(res + l, 1, 2);
          l += tlv_write_eos(res + l);
        } else if (cluster == 0x3e && attribute == 0x02) {
          l += tlv_write(res + l, 1, 2, (uint8_t)5);
        } else if (cluster == 0x3e && attribute == 0x03) {
          l += tlv_write(res + l, 1, 2, (uint8_t)0);
        } else {
          debug_dump("UNSUPPORTED READ", req, reqsize);
          return -INTERACTION_STATUS_UNSUPPORTED_ATTRIBUTE;
        }
      }
      l += tlv_write_eos(res + l);  // End AttributeData

      l += tlv_write_eos(res + l);  // End AttributeReportIB
    }
    l += tlv_write_eos(res + l);  // End AttributeReports
  }
  l += tlv_write_eos(res + l);
  return l;
}

int handle_write_report(PaseContext *ctx, const uint8_t *req, size_t reqsize,
                        uint8_t *res) {
  debug_dump("UNSUPPORTED WRITE", req, reqsize);
  return -INTERACTION_STATUS_UNSUPPORTED_WRITE;
}

int handle_invoke_command(PaseContext *ctx, const uint8_t *req, size_t reqsize,
                          uint8_t *res) {
  tag_info ti;
  int pos = 0, field_pos;
  pos += tlv_find_field(req + pos, reqsize - pos, 0, &ti);  // into struct
  pos += tlv_find_field(req + pos, reqsize - pos, 2, &ti);  // InvokeRequests
  pos += tlv_find_field(req + pos, reqsize - pos, 0, &ti);  // CommandDataIB[0]
  field_pos = pos + tlv_find_field(req + pos, reqsize - pos, 1, &ti);  // Fields
  pos += tlv_find_field(req + pos, reqsize - pos, 0, &ti);  // CommandPath
  pos += tlv_find_field(req + pos, reqsize - pos, 0, &ti);
  uint8_t endpoint = ti.val_or_len;
  pos += tlv_find_field(req + pos, reqsize - pos, 1, &ti);
  uint8_t cluster = ti.val_or_len;
  pos += tlv_find_field(req + pos, reqsize - pos, 2, &ti);
  uint8_t command = ti.val_or_len;

  int l = 0;
  // InvokeResponseMessage
  l += tlv_write_struct(res + l, 0, 0);
  {
    l += tlv_write(res + l, 1, 0, false);

    // InvokeResponses
    l += tlv_write_array(res + l, 1, 1);
    {
      // InvokeResponseIB
      l += tlv_write_struct(res + l, 0, 0);
      {
        // CommandDataIB
        l += tlv_write_struct(res + l, 1, 0);
        {
          // Path
          l += tlv_write_list(res + l, 1, 0);
          l += tlv_write(res + l, 1, 0, endpoint);
          l += tlv_write(res + l, 1, 1, cluster);
          l += tlv_write(res + l, 1, 2, command);
          l += tlv_write_eos(res + l);

          // CommandFields
          if (cluster == 0x3e && command == 0x02) {
            // CertificateChainRequest
            l += tlv_write_struct(res + l, 1, 1);
            l += tlv_write_str(res + l, 1, 0, kDACert, sizeof(kDACert));
            l += tlv_write_eos(res + l);
          } else if (cluster == 0x3e && command == 0x00) {
            // AttestationRequest
            field_pos += tlv_find_field(req + field_pos, reqsize - field_pos, 0,
                                        &ti);  // Nonce
            debug_dump("Nonce", ti.data_ref, ti.val_or_len);
            uint8_t elems[900], digest[32], sign[64];
            int p = tlv_write_struct(elems, 0, 0);
            p += tlv_write_str(elems + p, 1, 1, kCd, sizeof(kCd));
            p += tlv_write_str(elems + p, 1, 2, ti.data_ref,
                               ti.val_or_len);             // nonce
            p += tlv_write(elems + p, 1, 3, (uint32_t)0);  // TODO: timestamp
            p += tlv_write_eos(elems + p);
            SHA256 sha256;
            sha256.update(elems, p);
            sha256.update(ctx->keys + 32, 16);
            sha256.finish(digest);
            ecdsa_sign(digest, sizeof(digest), sign, kDACPrivateKey);
            l += tlv_write_struct(res + l, 1, 1);
            l += tlv_write_str(res + l, 1, 0, elems, p);
            l += tlv_write_str(res + l, 1, 1, sign, sizeof(sign));
            l += tlv_write_eos(res + l);
          } else if (cluster == 0x3e && command == 0x04) {
            // CSRRequest
            field_pos += tlv_find_field(req + field_pos, reqsize - field_pos, 0,
                                        &ti);  // Nonce
            debug_dump("Nonce", ti.data_ref, ti.val_or_len);
            uint8_t elems[900], digest[32], sign[64], csr[256];
            size_t csr_size = sizeof(csr);
            create_csr(kDACPrivateKey, kDACPublicKey, csr, &csr_size);
            int p = tlv_write_struct(elems, 0, 0);
            p += tlv_write_str(elems + p, 1, 1, csr, csr_size);
            p += tlv_write_str(elems + p, 1, 2, ti.data_ref,
                               ti.val_or_len);  // nonce
            p += tlv_write_eos(elems + p);
            SHA256 sha256;
            sha256.update(elems, p);
            sha256.update(ctx->keys + 32, 16);
            sha256.finish(digest);
            ecdsa_sign(digest, sizeof(digest), sign, kDACPrivateKey);
            l += tlv_write_struct(res + l, 1, 1);
            l += tlv_write_str(res + l, 1, 0, elems, p);
            l += tlv_write_str(res + l, 1, 1, sign, sizeof(sign));
            l += tlv_write_eos(res + l);
          } else if (cluster == 0x3e && (command == 0x06 || command == 0x07 ||
                                         command == 0x09 || command == 0x0B)) {
            // NOCResponse
            l += tlv_write_struct(res + l, 1, 1);
            l += tlv_write(res + l, 1, 0, (uint8_t)0);
            l += tlv_write(res + l, 1, 1, (uint8_t)1);
            l += tlv_write_str(res + l, 1, 2, nullptr, 0);
            l += tlv_write_eos(res + l);
          } else if (cluster == 0x30 && command == 0x00) {
            // ArmFailSafe
            l += tlv_write_struct(res + l, 1, 1);
            l += tlv_write(res + l, 1, 0, (uint8_t)0);
            l += tlv_write_eos(res + l);
          } else if (cluster == 0x30 && command == 0x02) {
            // SetRegulatoryConfig
            l += tlv_write_struct(res + l, 1, 1);
            l += tlv_write(res + l, 1, 0, (uint8_t)0);
            l += tlv_write_eos(res + l);
          } else if (cluster == 0x31 && command == 0x02) {
            // AddOrUpdateWiFiNetwork
            field_pos += tlv_find_field(req + field_pos, reqsize - field_pos, 0,
                                        &ti);  // SSID
            if (ti.data_ref) {
              debug_dump("SSID", ti.data_ref, ti.val_or_len);
            }
            field_pos += tlv_find_field(req + field_pos, reqsize - field_pos, 1,
                                        &ti);  // PASSWD
            if (ti.data_ref) {
              debug_dump("PASSWORD", ti.data_ref, ti.val_or_len);
            }
            l += tlv_write_struct(res + l, 1, 1);
            l += tlv_write(res + l, 1, 0, (uint8_t)0);  // Success
            l += tlv_write_eos(res + l);
          } else if (cluster == 0x31 && command == 0x06) {
            // Connect
            l += tlv_write_struct(res + l, 1, 1);
            l += tlv_write(res + l, 1, 0, (uint8_t)12);  // Unknown Error
            l += tlv_write_str(res + l, 1, 1, (uint8_t *)"Connecting...",
                               13);  // DebugText
            l += tlv_write_eos(res + l);
          } else {
            debug_dump("UNSUPPORTED INVOKE", req, reqsize);
            return -INTERACTION_STATUS_UNSUPPORTED_COMMAND;
          }
        }
        l += tlv_write_eos(res + l);
        // End CommandDataIB
        /*
                // CommandStatusIB
                l += tlv_write_struct(res + l, 1, 1);
                {
                  // Path
                  l += tlv_write_list(res + l, 1, 0);
                  l += tlv_write(res + l, 1, 0, endpoint);
                  l += tlv_write(res + l, 1, 1, cluster);
                  l += tlv_write(res + l, 1, 2, command);
                  l += tlv_write_eos(res + l);

                  // Status
                  l += tlv_write_struct(res + l, 1, 1);
                  l += tlv_write(res + l, 1, 0, (uint8_t)0);
                  l += tlv_write(res + l, 1, 1, (uint8_t)0);
                  l += tlv_write_eos(res + l);
                }
                l += tlv_write_eos(res + l);  // End CommandStatusIB
                */
      }
      l += tlv_write_eos(res + l);  // End InvokeResponseIB
    }
    l += tlv_write_eos(res + l);  // End InvokeResponses
    // l += tlv_write(res + l, 1, 255, 10);  // InteractionModelRevision
  }
  l += tlv_write_eos(res + l);
  debug_dump("INVOKE RES", res, l);
  return l;
}

inline int handle_message(PaseContext *ctx, uint8_t *req, int reqsize,
                          uint8_t *res) {
  // TODO: check message type
  int sz = 0;
  if (ctx->msg_count == 1) {
    sz = handle_pbdkreq(ctx, req, reqsize, res);
  } else if (ctx->msg_count == 2) {
    sz = handle_pake1(ctx, req, reqsize, res);
  } else if (ctx->msg_count == 3) {
    sz = handle_pake3(ctx, req, reqsize, res);
  } else if (ctx->msg_count >= 4) {
    uint8_t *plain = req + message_get_header_size(req);
    int len = decrypt_message(ctx, req, reqsize, plain);
    if (message_get_proto_id(plain) == MSG_PROTO_ID_INTERACTION_MODEL) {
      uint16_t exchange_id = message_get_proto_echange_id(plain);
      int hl = message_get_pheader_size(plain);
      int mhl = message_write_header(res, ctx->session_id, ctx->msg_count, 0);
      int ret = 0, phl = 0;
      if (message_get_proto_op(plain) == MSG_PROTO_OP_INTERACTION_READ) {
        phl = message_write_pheader(res + mhl, MSG_PROTO_OP_INTERACTION_DATA,
                                    exchange_id, MSG_PROTO_ID_INTERACTION_MODEL,
                                    0);
        ret = handle_read_report(ctx, plain + hl, len - hl, res + mhl + phl);
      } else if (message_get_proto_op(plain) ==
                 MSG_PROTO_OP_INTERACTION_WRITE) {
        phl = message_write_pheader(
            res + mhl, MSG_PROTO_OP_INTERACTION_WRITE_RES, exchange_id,
            MSG_PROTO_ID_INTERACTION_MODEL, 0);
        ret = handle_write_report(ctx, plain + hl, len - hl, res + mhl + phl);
      } else if (message_get_proto_op(plain) ==
                 MSG_PROTO_OP_INTERACTION_INVOKE) {
        phl = message_write_pheader(
            res + mhl, MSG_PROTO_OP_INTERACTION_INVOKE_RES, exchange_id,
            MSG_PROTO_ID_INTERACTION_MODEL, 0);
        ret = handle_invoke_command(ctx, plain + hl, len - hl, res + mhl + phl);
      }
      if (ret <= 0) {
        uint8_t status = -ret;
        phl = message_write_pheader(res + mhl, MSG_PROTO_OP_INTERACTION_STATUS,
                                    exchange_id, MSG_PROTO_ID_INTERACTION_MODEL,
                                    0);
        ret = 0;
        ret += tlv_write_struct(res + mhl + phl + ret, 0, 0);
        ret += tlv_write(res + mhl + phl + ret, 1, 0, status);
        ret += tlv_write_eos(res + mhl + phl + ret);
      }
      if (ret > 0) {
        sz = encrypt_message(ctx, res, mhl + phl + ret, res + mhl);
      }
    }
  }
  return sz;
}

uint16_t check_btp_packet_send(PaseContext *ctx, uint8_t **data) {
  if (ctx->send_pos >= ctx->send_size && ctx->recv_size > 0 &&
      (ctx->recv_buf[0] & BTP_E_MASK) != 0) {
    uint8_t *req = ctx->recv_buf;
    size_t reqsize = ctx->recv_size;
    ctx->recv_size = 0;
    if (req[0] == 0x65) {
      ctx->msg_count = 1;
      ctx->btp_tx_seq = 0;
      *data = ctx->send_buf;
      return handle_btp_handshake(ctx, req, reqsize, ctx->send_buf);
    }
    if (reqsize < 6) {
      return 0;
    }
    int p = btp_get_header_size(req);

    int sz = handle_message(ctx, req + p, reqsize - p,
                            ctx->send_buf + BTP_MAX_HEADER_SIZE);
    if (sz == 0) {
      // TODO ack
      /*
        if (req[0] == BTP_A_MASK) {
          res[0] = BTP_A_MASK;
          res[1] = btp_get_seq(req);
          res[2] = ctx->btp_count + 1;
          return 3;
        }
        ctx->btp_count++;
        */
      return 0;
    }
    ctx->msg_count++;
    ctx->send_pos = BTP_MAX_HEADER_SIZE;
    ctx->send_size = sz + BTP_MAX_HEADER_SIZE;
  }
  if (ctx->send_pos >= ctx->send_size) {
    return 0;
  }
  uint8_t flags = ctx->send_pos == BTP_MAX_HEADER_SIZE ? BTP_B_MASK | BTP_A_MASK
                                                       : BTP_C_FLAG;
  uint16_t sz = ctx->send_size - ctx->send_pos;
  uint16_t hsz = btp_get_header_size(flags);
  if (sz > 244 - hsz) {
    sz = 244 - hsz;
  } else {
    flags |= BTP_E_MASK;
  }
  uint8_t *buf = ctx->send_buf + ctx->send_pos - hsz;
  btp_write_header_f(buf, flags, ctx->btp_rx_seq, ++ctx->btp_tx_seq,
                     ctx->send_size - ctx->send_pos);
  ctx->send_pos += sz;
  *data = buf;
  return sz + hsz;
}

int handle_btp_packet(PaseContext *ctx, const uint8_t *req, int reqsize) {
  debug_dump("RECV BTP", req, reqsize);
  if (reqsize < 2 || (req[0] & (BTP_B_MASK | BTP_E_MASK | BTP_C_FLAG)) == 0) {
    return 0;  // no message data
  }
  if (ctx->recv_size > 0 && (ctx->recv_buf[0] & BTP_E_MASK) == 0) {
    // concat packets
    size_t hl = btp_get_header_size(req);
    memcpy(ctx->recv_buf + ctx->recv_size, req + hl, reqsize - hl);
    ctx->btp_rx_seq = btp_get_seq(req);
    ctx->recv_size += reqsize - hl;
    ctx->recv_buf[0] |= req[0] & BTP_E_MASK;
    return 0;
  }
  if (ctx->recv_size > 0) {
    return 1;  // busy
  }
  memcpy(ctx->recv_buf, req, reqsize);
  ctx->recv_size = reqsize;
  ctx->btp_rx_seq = btp_get_seq(req);
  return 0;
}
