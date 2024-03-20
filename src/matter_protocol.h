#include <stdint.h>

#define BTP_H_MASK 0x40
#define BTP_M_MASK 0x20
#define BTP_A_MASK 0x08
#define BTP_E_MASK 0x04
#define BTP_B_MASK 0x01

static int btp_get_header_size(const uint8_t *buf) {
  int sz = 1;
  if (buf[0] & BTP_A_MASK) {
    sz++;
  }
  if ((buf[0] & BTP_H_MASK) == 0) {
    sz++;
  }
  if (buf[0] & BTP_B_MASK) {
    sz += 2;
  }
  return sz;
}

static int btp_write_header(uint8_t *buf, uint8_t ack, uint8_t seq,
                            uint16_t size) {
  buf[0] = BTP_A_MASK | BTP_E_MASK | BTP_B_MASK;
  buf[1] = ack;
  buf[2] = seq;
  buf[3] = size & 0xff;
  buf[4] = size >> 8;
  return 5;
}

static void btp_update_size(uint8_t *buf, uint16_t size) {
  buf[3] = size & 0xff;
  buf[4] = size >> 8;
}

#define MSG_FLAG_S 0x04
#define MSG_FLAG_DSIZ_MASK 0x03
#define MSG_FLAG_DSIZ_64 0x01
#define MSG_FLAG_DSIZ_16 0x02

#define MSG_PROTO_FLAG_V 0x10
#define MSG_PROTO_FLAG_SX 0x08
#define MSG_PROTO_FLAG_R 0x04
#define MSG_PROTO_FLAG_A 0x02
#define MSG_PROTO_FLAG_I 0x01

#define MSG_PROTO_ID_SECURE 0x0000
#define MSG_PROTO_OP_PBKD_REQ 0x20
#define MSG_PROTO_OP_PBKD_RES 0x21
#define MSG_PROTO_OP_PASE_PAKE1 0x22
#define MSG_PROTO_OP_PASE_PAKE2 0x23
#define MSG_PROTO_OP_PASE_PAKE3 0x24
#define MSG_PROTO_OP_STATUS_REPORT 0x40

static int message_get_header_size(const uint8_t *buf) {
  int sz = 8;
  if (buf[0] & MSG_FLAG_S) {
    sz += 8;
  }
  if ((buf[0] & MSG_FLAG_DSIZ_MASK) == 1) {
    sz += 8;  // 64bit
  } else if ((buf[0] & MSG_FLAG_DSIZ_MASK) == 2) {
    sz += 2;  // 16bit
  }
  return sz;
}

static uint64_t message_get_sender(const uint8_t *buf) {
  if (buf[0] & MSG_FLAG_S) {
    uint32_t l = buf[8] | buf[9] << 8 | buf[10] << 16 | uint32_t(buf[11]) << 24;
    uint32_t h =
        buf[12] | buf[13] << 8 | buf[14] << 16 | uint32_t(buf[15]) << 24;
    return uint64_t(l) | uint64_t(h) << 32;
  }
  return 0;
}

static int message_get_pheader_size(const uint8_t *buf) {
  int sz = 6;
  if (buf[0] & MSG_PROTO_FLAG_V) {
    sz += 2;
  }
  if (buf[0] & MSG_PROTO_FLAG_A) {
    sz += 4;
  }
  return sz;
}

static uint32_t message_get_counter(const uint8_t *buf) {
  return buf[4] | buf[5] << 8 | buf[6] << 16 | buf[7] << 24;
}

static int message_write_header(uint8_t *buf, uint16_t session,
                                uint32_t msgcount, uint64_t dst64) {
  buf[0] = dst64 ? MSG_FLAG_DSIZ_64 : 0;  // MSG_FLAG_S;
  buf[1] = session;
  buf[2] = session >> 8;
  buf[3] = 0;
  buf[4] = msgcount;
  buf[5] = msgcount >> 8;
  buf[6] = msgcount >> 16;
  buf[7] = msgcount >> 24;
  int sz = 8;
  if (dst64) {
    sz += 8;
    buf[8] = dst64;
    buf[9] = dst64 >> 8;
    buf[10] = dst64 >> 16;
    buf[11] = dst64 >> 24;
    buf[12] = dst64 >> 32;
    buf[13] = dst64 >> 40;
    buf[14] = dst64 >> 48;
    buf[15] = dst64 >> 56;
  }
  return sz;
}

static uint8_t message_get_proto_op(const uint8_t *buf) { return buf[1]; }

static uint16_t message_get_proto_echange_id(const uint8_t *buf) {
  return buf[2] | buf[3] << 8;
}

static int message_write_pheader(uint8_t *buf, uint8_t op, uint16_t ex,
                                 uint16_t proto, uint32_t ack) {
  int sz = 6;
  buf[0] = ack ? MSG_PROTO_FLAG_A : 0;
  buf[1] = op;
  buf[2] = ex;
  buf[3] = ex >> 8;
  buf[4] = proto;
  buf[5] = proto >> 8;
  if (ack) {
    buf[6] = ack;
    buf[7] = ack >> 8;
    buf[8] = ack >> 16;
    buf[9] = ack >> 24;
    sz += 4;
  }
  return sz;
}

#define MSG_STATUS_REPORT_SUCCESS 0x00
#define MSG_STATUS_REPORT_FAILURE 0x01
#define MSG_STATUS_REPORT_SESSION_ESTABLISHMENT_SUCCESS 0x0000

static int write_status_report(uint8_t *buf, uint16_t generic_code,
                                       uint16_t status) {
  buf[0] = generic_code;
  buf[1] = generic_code >> 8;
  buf[2] = MSG_PROTO_ID_SECURE;
  buf[3] = MSG_PROTO_ID_SECURE >> 8;
  buf[4] = MSG_PROTO_ID_SECURE >> 16;
  buf[5] = MSG_PROTO_ID_SECURE >> 24;
  buf[6] = status;
  buf[7] = status >> 8;
  return 8;
}

#define TLV_TAG_TYPE_MASK 0xe0
#define TLV_TAG_TYPE_ANONYMOUS (0 << 5)
#define TLV_TAG_TYPE_CONTEXT_1 (1 << 5)
#define TLV_TAG_TYPE_CONTEXT_2 (2 << 5)
#define TLV_TAG_TYPE_CONTEXT_4 (3 << 5)

#define TLV_VAL_TYPE_MASK 0x1f
#define TLV_VAL_TYPE_INT8 0x00
#define TLV_VAL_TYPE_INT16 0x01
#define TLV_VAL_TYPE_INT32 0x02
#define TLV_VAL_TYPE_INT64 0x03
#define TLV_VAL_TYPE_UINT8 0x04
#define TLV_VAL_TYPE_UINT16 0x05
#define TLV_VAL_TYPE_UINT32 0x06
#define TLV_VAL_TYPE_UINT64 0x07
#define TLV_VAL_TYPE_FALSE 0x08
#define TLV_VAL_TYPE_TRUE 0x09
#define TLV_VAL_TYPE_FLOAT32 0x0A
#define TLV_VAL_TYPE_FLOAT64 0x0B
#define TLV_VAL_TYPE_UTF8_1 0x0C
#define TLV_VAL_TYPE_UTF8_2 0x0D
#define TLV_VAL_TYPE_UTF8_4 0x0E
#define TLV_VAL_TYPE_UTF8_8 0x0F
#define TLV_VAL_TYPE_STRING_1 0x10
#define TLV_VAL_TYPE_STRING_2 0x11
#define TLV_VAL_TYPE_STRING_4 0x12
#define TLV_VAL_TYPE_STRING_8 0x13
#define TLV_VAL_TYPE_NULL 0x14
#define TLV_VAL_TYPE_STRUCT 0x15
#define TLV_VAL_TYPE_ARRAY 0x16
#define TLV_VAL_TYPE_LIST 0x17
#define TLV_VAL_TYPE_END 0x18

static const uint8_t tag_len[] = {0, 1, 2, 4, 2, 4, 6, 8};
static const uint8_t val_len[] = {
    1,    2,    4,    8,    1, 2, 4, 8, 0, 0, 4, 8, 0x11, 0x12, 0x14, 0x18,
    0x11, 0x12, 0x14, 0x18, 0, 0, 0, 0, 0, 0, 0, 0, 0,    0,    0,    0};

static int write_tag(uint8_t *buf, uint8_t tag_type, uint16_t tag) {
  int tl = tag_len[tag_type];
  if (tl == 1) {
    buf[0] = tag;
  } else if (tl >= 2) {
    buf[0] = tag;
    buf[1] = tag >> 8;
  }
  return tl;
}

static int tlv_write(uint8_t *buf, uint8_t tag_type, uint16_t tag, bool v) {
  buf[0] = tag_type << 5 | (v ? TLV_VAL_TYPE_TRUE : TLV_VAL_TYPE_FALSE);
  return 1 + write_tag(&buf[1], tag_type, tag);
}

static int tlv_write_struct(uint8_t *buf, uint8_t tag_type, uint16_t tag) {
  buf[0] = tag_type << 5 | TLV_VAL_TYPE_STRUCT;
  return 1 + write_tag(&buf[1], tag_type, tag);
}

static int tlv_write_array(uint8_t *buf, uint8_t tag_type, uint16_t tag) {
  buf[0] = tag_type << 5 | TLV_VAL_TYPE_ARRAY;
  return 1 + write_tag(&buf[1], tag_type, tag);
}

static int tlv_write_list(uint8_t *buf, uint8_t tag_type, uint16_t tag) {
  buf[0] = tag_type << 5 | TLV_VAL_TYPE_LIST;
  return 1 + write_tag(&buf[1], tag_type, tag);
}

static inline void tlv_write16(uint8_t *buf, uint16_t v) {
  buf[0] = v;
  buf[1] = v >> 8;
}

static inline void tlv_write32(uint8_t *buf, uint32_t v) {
  buf[0] = v;
  buf[1] = v >> 8;
  buf[2] = v >> 16;
  buf[3] = v >> 24;
}

static int tlv_write(uint8_t *buf, uint8_t tag_type, uint16_t tag, int8_t v) {
  buf[0] = tag_type << 5 | TLV_VAL_TYPE_INT8;
  int sz = 1 + write_tag(&buf[1], tag_type, tag);
  buf[sz] = v;
  sz += 1;
  return sz;
}

static int tlv_write(uint8_t *buf, uint8_t tag_type, uint16_t tag, uint8_t v) {
  buf[0] = tag_type << 5 | TLV_VAL_TYPE_UINT8;
  int sz = 1 + write_tag(&buf[1], tag_type, tag);
  buf[sz] = v;
  sz += 1;
  return sz;
}

static int tlv_write(uint8_t *buf, uint8_t tag_type, uint16_t tag, int16_t v) {
  buf[0] = tag_type << 5 | TLV_VAL_TYPE_INT16;
  int sz = 1 + write_tag(&buf[1], tag_type, tag);
  tlv_write16(&buf[sz], (uint16_t)v);
  sz += 2;
  return sz;
}

int tlv_write(uint8_t *buf, uint8_t tag_type, uint16_t tag, uint16_t v) {
  buf[0] = tag_type << 5 | TLV_VAL_TYPE_UINT16;
  int sz = 1 + write_tag(&buf[1], tag_type, tag);
  tlv_write16(&buf[sz], (uint16_t)v);
  sz += 2;
  return sz;
}

static int tlv_write(uint8_t *buf, uint8_t tag_type, uint16_t tag, int32_t v) {
  buf[0] = tag_type << 5 | TLV_VAL_TYPE_INT32;
  int sz = 1 + write_tag(&buf[1], tag_type, tag);
  tlv_write32(&buf[sz], (uint32_t)v);
  sz += 4;
  return sz;
}

static int tlv_write(uint8_t *buf, uint8_t tag_type, uint16_t tag, uint32_t v) {
  buf[0] = tag_type << 5 | TLV_VAL_TYPE_UINT32;
  int sz = 1 + write_tag(&buf[1], tag_type, tag);
  tlv_write32(&buf[sz], (uint32_t)v);
  sz += 4;
  return sz;
}

static int tlv_write_null(uint8_t *buf, uint8_t tag_type, uint16_t tag) {
  buf[0] = tag_type << 5 | TLV_VAL_TYPE_NULL;
  int sz = 1 + write_tag(&buf[1], tag_type, tag);
  return sz;
}

static int tlv_write_str(uint8_t *buf, uint8_t tag_type, uint16_t tag,
                         const uint8_t *v, int len) {
  buf[0] = tag_type << 5 | TLV_VAL_TYPE_STRING_1;
  int sz = 1 + write_tag(&buf[1], tag_type, tag);
  buf[sz] = len;
  sz++;
  for (int i = 0; i < len; i++) {
    buf[sz] = v[i];
    sz++;
  }
  return sz;
}

static int tlv_write_eos(uint8_t *buf) {
  buf[0] = TLV_VAL_TYPE_END;
  return 1;
}

static uint32_t tlv_read_int(const uint8_t *buf, uint8_t l) {
  uint32_t v = 0;
  if (l == 1) {
    v = buf[0];
  } else if (l == 2) {
    v = uint32_t(buf[0]) | (uint32_t(buf[1]) << 8);
  } else if (l >= 4) {
    v = uint32_t(buf[0]) | (uint32_t(buf[1]) << 8) | (uint32_t(buf[2]) << 16) |
        (uint32_t(buf[3]) << 16);
  }
  return v;
}

struct tag_info {
  uint8_t tag_type;
  uint8_t val_type;
  uint32_t tag;
  uint32_t val_or_len;
  const uint8_t *data_ref;
};

static int tlv_read_tag(const uint8_t *buf, tag_info *ti) {
  int tag_type = (buf[0] & TLV_TAG_TYPE_MASK) >> 5;
  int val_type = buf[0] & TLV_VAL_TYPE_MASK;
  int tl = tag_len[tag_type];
  uint32_t tag = tlv_read_int(&buf[1], tl);
  int vl = val_len[val_type];
  int sz = 1 + tl;
  int val_or_len = tlv_read_int(&buf[sz], vl & 0x0f);
  sz += vl & 0x0f;
  ti->tag_type = tag_type;
  ti->val_type = val_type;
  ti->tag = tag;
  ti->val_or_len = val_or_len;
  if (vl & 0x10) {
    ti->data_ref = &buf[sz];
    sz += val_or_len;
  } else {
    ti->data_ref = nullptr;
  }
  return sz;
}
