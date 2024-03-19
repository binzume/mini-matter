#include <iostream>

#include "../src/matter_protocol.h"
using namespace std;

void hexdump(const uint8_t *buf, int sz) {
  std::cout << std::hex;
  for (int i = 0; i < sz; i++) {
    if (buf[i] < 16) {
      std::cout << "0";
    }
    std::cout << (int)buf[i];
    if (i != sz - 1) std::cout << ",";
  }
  std::cout << std::dec;
}

int tlv_print_tag(const uint8_t *buf) {
  tag_info ti;
  int sz = tlv_read_tag(buf, &ti);

  if (ti.tag_type == 0) {
    cout << "[] ";
  } else {
    cout << "ACCCIIFF"[ti.tag_type] << "[" << ti.tag << "] ";
  }

  const char *names[] = {
      "i",     "i",    "i",       "i",       "ui",   "ui",     "ui",    "ui",
      "false", "true", "float32", "float64", "utf8", "utf8",   "utf8",  "utf8",
      "str",   "str",  "str",     "str",     "null", "struct", "array", "list",
      "end",   "#",    "#",       "#",       "#",    "#",      "#",     "#"};
  cout << names[ti.val_type];
  if (ti.data_ref) {
    cout << "(" << ti.val_or_len << ") ";
    hexdump(ti.data_ref, ti.val_or_len);
  } else if (ti.val_type <= 0x0b) {
    cout << " " << ti.val_or_len;
  }
  cout << endl;
  return sz;
}

void tlv_dump(const uint8_t *buf, int l) {
  int pos = 0;
  while (pos < l) {
    pos += tlv_print_tag(buf + pos);
  }
}

void packet_dump(const uint8_t *buf, int l) {
  int pos = 0;
  pos += btp_get_header_size(buf);
  pos += message_get_header_size(buf + pos);
  pos += message_get_pheader_size(buf + pos);
  cout << pos << endl;
  tlv_dump(&buf[pos], l - pos);
}

int main() {
  uint8_t pbdkreq[] = {
      // BTP(A,E,B)
      0x0D, 0x00, 0x00, 0x62, 0x00,  // F, ACK, SEQ, LEN[2]
      // Message Header(S)
      0x04, 0x00, 0x00, 0x00, 0xAE, 0x8C, 0x43, 0x04, 0x84, 0x18, 0x9E, 0xAD,
      0x9A, 0x76, 0x73, 0xFA,
      // Protocol Header
      0x01, 0x20, 0x2C, 0xB1, 0x00, 0x00,
      // Payload (76) PBKDFParamResponse
      0x15, 0x30, 0x01, 0x20, 0x44, 0x05, 0xAE, 0x1E, 0x6E, 0x9F, 0xAF, 0x4F,
      0x80, 0x86, 0x8A, 0x51, 0xBF, 0x8B, 0x4C, 0xDD, 0xDA, 0x27, 0x5F, 0x2F,
      0xC3, 0xD4, 0x0E, 0xEF, 0xCD, 0x0B, 0x9E, 0xF4, 0x2B, 0x4C, 0xD7, 0x0E,
      0x25, 0x02, 0x23, 0xCC, 0x24, 0x03, 0x00, 0x28, 0x04, 0x35, 0x05, 0x25,
      0x01, 0x2C, 0x01, 0x25, 0x02, 0x2C, 0x01, 0x25, 0x03, 0xA0, 0x0F, 0x24,
      0x04, 0x11, 0x24, 0x05, 0x0B, 0x26, 0x06, 0x00, 0x00, 0x03, 0x01, 0x24,
      0x07, 0x01, 0x18, 0x18};

  uint8_t pbdkres[] = {
      13, 0, 1, 124, 0,
      // Message
      1, 0, 0, 0, 75, 236, 203, 7, 132, 24, 158, 173, 154, 118, 115, 250,
      // Proto
      0, 33, 44, 177, 0, 0,
      // Payload
      21, 48, 1, 32, 68, 5, 174, 30, 110, 159, 175, 79, 128, 134, 138, 81, 191,
      139, 76, 221, 218, 39, 95, 47, 195, 212, 14, 239, 205, 11, 158, 244, 43,
      76, 215, 14, 48, 2, 32, 58, 147, 181, 72, 14, 179, 85, 7, 181, 232, 96,
      52, 71, 236, 42, 228, 80, 41, 156, 38, 230, 33, 217, 11, 19, 121, 190, 86,
      186, 162, 117, 64, 37, 3, 124, 27, 53, 4, 37, 1, 232, 3, 48, 2, 16, 83,
      80, 65, 75, 69, 50, 80, 32, 75, 101, 121, 32, 83, 97, 108, 116, 24, 24};

  // D,0,0,62,0
  // 4,0,0,0,9F,D3,27,0,12,B8,B5,B7,F8,A2,62,A0,
  // 1,20,C,7F,0,0,
  // 15,30,1,20,6F,29,3B,9B,B0,63,79,5D,8E,91,3A,58,B0,1F,C3,E0,10,6F,86,3,95,FA,32,23,4B,16,39,F0,34,0,29,B7,25,2,EE,E7,24,3,0,28,4,35,5,25,1,2C,1,25,2,2C,1,25,3,A0,F,24,4,11,24,5,B,26,6,0,0,3,1,24,7,1,18,18
  uint8_t pake1[] = {// BTP
                     0xD, 0x1, 0x1, 0x5C, 0x0,
                     // Msg
                     0x4, 0x0, 0x0, 0x0, 0xA0, 0xD3, 0x27, 0x0, 0x12, 0xB8,
                     0xB5, 0xB7, 0xF8, 0xA2, 0x62, 0xA0,
                     // Proto
                     0x1, 0x22, 0xC, 0x7F, 0x0, 0x0,
                     // Data
                     0x15, 0x30, 0x1, 0x41, 0x4, 0x19, 0x5C, 0x6F, 0x9F, 0xD6,
                     0x94, 0x2D, 0x4A, 0x8F, 0x44, 0x5, 0x57, 0x53, 0x51, 0xD4,
                     0x48, 0x64, 0xBA, 0xDC, 0x30, 0x53, 0xB2, 0xFF, 0xAD, 0xAF,
                     0xD7, 0xB5, 0xC, 0x5C, 0xB3, 0x65, 0xD2, 0xDF, 0x2E, 0x7B,
                     0x89, 0x3D, 0x70, 0x17, 0x45, 0x47, 0xF7, 0x8B, 0x23, 0x63,
                     0x93, 0xA7, 0x81, 0x69, 0x73, 0x7F, 0x43, 0xD5, 0x78, 0xC7,
                     0xEB, 0x81, 0x13, 0xF, 0xFA, 0xA0, 0x8A, 0xE8, 0xF9, 0x18};

// [,D,2,2,1E,0,4,0,0,0,1D,F8,49,4,9D,80,36,D1,EF,63,21,B6,1,40,99,F3,0,0,1,0,0,0,0,0,2,0]
  packet_dump(pbdkreq, sizeof(pbdkreq));
  cout << endl;
  packet_dump(pbdkres, sizeof(pbdkres));
  cout << endl;
  packet_dump(pake1, sizeof(pake1));
  cout << endl;

  /*
    // PBKDFParamResponse
    uint8_t res[256];
    int l = make_pbdkres(nullptr, pbdkreq, sizeof(pbdkreq), res);
    hexdump(res, l);
    cout << endl;
    packet_dump(res, l);

    l = make_pake2(nullptr, pake1, sizeof(pake1), res);
    hexdump(res, l);
    cout << endl;
    packet_dump(res, l);
  */
  return 0;
}
