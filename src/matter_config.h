
#define DEVICE_DISCRIMINATOR 3840
#define BLE_VENDOR_ID 0xFFF1
#define BLE_PRODUCT_ID 0x8000
#define PIN 20202021

// pairing code 34970112332

// DA Cert for FFF1:8000
// from ExampleDACs.cpp
const unsigned char kDACert[] = {
    0x30, 0x82, 0x01, 0xe9, 0x30, 0x82, 0x01, 0x8e, 0xa0, 0x03, 0x02, 0x01,
    0x02, 0x02, 0x08, 0x23, 0x8a, 0x64, 0x7b, 0xbc, 0x4c, 0x30, 0xdd, 0x30,
    0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30,
    0x3d, 0x31, 0x25, 0x30, 0x23, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x1c,
    0x4d, 0x61, 0x74, 0x74, 0x65, 0x72, 0x20, 0x44, 0x65, 0x76, 0x20, 0x50,
    0x41, 0x49, 0x20, 0x30, 0x78, 0x46, 0x46, 0x46, 0x31, 0x20, 0x6e, 0x6f,
    0x20, 0x50, 0x49, 0x44, 0x31, 0x14, 0x30, 0x12, 0x06, 0x0a, 0x2b, 0x06,
    0x01, 0x04, 0x01, 0x82, 0xa2, 0x7c, 0x02, 0x01, 0x0c, 0x04, 0x46, 0x46,
    0x46, 0x31, 0x30, 0x20, 0x17, 0x0d, 0x32, 0x32, 0x30, 0x32, 0x30, 0x35,
    0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x18, 0x0f, 0x39, 0x39, 0x39,
    0x39, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33, 0x35, 0x39, 0x35, 0x39, 0x5a,
    0x30, 0x53, 0x31, 0x25, 0x30, 0x23, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c,
    0x1c, 0x4d, 0x61, 0x74, 0x74, 0x65, 0x72, 0x20, 0x44, 0x65, 0x76, 0x20,
    0x44, 0x41, 0x43, 0x20, 0x30, 0x78, 0x46, 0x46, 0x46, 0x31, 0x2f, 0x30,
    0x78, 0x38, 0x30, 0x30, 0x30, 0x31, 0x14, 0x30, 0x12, 0x06, 0x0a, 0x2b,
    0x06, 0x01, 0x04, 0x01, 0x82, 0xa2, 0x7c, 0x02, 0x01, 0x0c, 0x04, 0x46,
    0x46, 0x46, 0x31, 0x31, 0x14, 0x30, 0x12, 0x06, 0x0a, 0x2b, 0x06, 0x01,
    0x04, 0x01, 0x82, 0xa2, 0x7c, 0x02, 0x02, 0x0c, 0x04, 0x38, 0x30, 0x30,
    0x30, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d,
    0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
    0x03, 0x42, 0x00, 0x04, 0x62, 0xdb, 0x16, 0xba, 0xde, 0xa3, 0x26, 0xa6,
    0xdb, 0x84, 0x81, 0x4a, 0x06, 0x3f, 0xc6, 0xc7, 0xe9, 0xe2, 0xb1, 0x01,
    0xb7, 0x21, 0x64, 0x8e, 0xba, 0x4e, 0x5a, 0xc8, 0x40, 0xf5, 0xda, 0x30,
    0x1e, 0xe6, 0x18, 0x12, 0x4e, 0xb4, 0x18, 0x0e, 0x2f, 0xc3, 0xa2, 0x04,
    0x7a, 0x56, 0x4b, 0xa9, 0xbc, 0xfa, 0x0b, 0xf7, 0x1f, 0x60, 0xce, 0x89,
    0x30, 0xf1, 0xe7, 0xf6, 0x6e, 0xc8, 0xd7, 0x28, 0xa3, 0x60, 0x30, 0x5e,
    0x30, 0x0c, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x02,
    0x30, 0x00, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff,
    0x04, 0x04, 0x03, 0x02, 0x07, 0x80, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d,
    0x0e, 0x04, 0x16, 0x04, 0x14, 0xbc, 0xf7, 0xb0, 0x07, 0x49, 0x70, 0x63,
    0x60, 0x6a, 0x26, 0xbe, 0x4e, 0x08, 0x7c, 0x59, 0x56, 0x87, 0x74, 0x5a,
    0x5a, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16,
    0x80, 0x14, 0x63, 0x54, 0x0e, 0x47, 0xf6, 0x4b, 0x1c, 0x38, 0xd1, 0x38,
    0x84, 0xa4, 0x62, 0xd1, 0x6c, 0x19, 0x5d, 0x8f, 0xfb, 0x3c, 0x30, 0x0a,
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x49,
    0x00, 0x30, 0x46, 0x02, 0x21, 0x00, 0x97, 0x97, 0x11, 0xec, 0x9e, 0x76,
    0x18, 0xce, 0x41, 0x80, 0x11, 0x32, 0xc2, 0x50, 0xdb, 0x70, 0x76, 0x74,
    0x63, 0x0c, 0xd5, 0x8c, 0x12, 0xc6, 0xe2, 0x31, 0x5f, 0x08, 0xd0, 0x1e,
    0xe1, 0x78, 0x02, 0x21, 0x00, 0xec, 0xfc, 0x13, 0x06, 0xbd, 0x2a, 0x13,
    0x3d, 0x12, 0x2a, 0x27, 0x86, 0x10, 0xea, 0x3d, 0xca, 0x47, 0xf0, 0x5c,
    0x7a, 0x8b, 0x80, 0x5f, 0xa7, 0x1c, 0x6f, 0xf4, 0x15, 0x38, 0xa8, 0x64,
    0xc8};

const uint8_t kDACPrivateKey[32] = {
    0xcc, 0xcf, 0x9d, 0xc7, 0x05, 0x0e, 0xf5, 0xd9, 0x0b, 0xe4, 0x57,
    0x07, 0xb9, 0x0e, 0x1f, 0x87, 0x5d, 0x59, 0xbe, 0x1f, 0xa9, 0x42,
    0xe8, 0xed, 0x2e, 0x42, 0x72, 0x03, 0xf6, 0xc2, 0xee, 0x3d,
};

const uint8_t kDACPublicKey[65] = {
    0x04, 0x62, 0xdb, 0x16, 0xba, 0xde, 0xa3, 0x26, 0xa6, 0xdb, 0x84,
    0x81, 0x4a, 0x06, 0x3f, 0xc6, 0xc7, 0xe9, 0xe2, 0xb1, 0x01, 0xb7,
    0x21, 0x64, 0x8e, 0xba, 0x4e, 0x5a, 0xc8, 0x40, 0xf5, 0xda, 0x30,
    0x1e, 0xe6, 0x18, 0x12, 0x4e, 0xb4, 0x18, 0x0e, 0x2f, 0xc3, 0xa2,
    0x04, 0x7a, 0x56, 0x4b, 0xa9, 0xbc, 0xfa, 0x0b, 0xf7, 0x1f, 0x60,
    0xce, 0x89, 0x30, 0xf1, 0xe7, 0xf6, 0x6e, 0xc8, 0xd7, 0x28,
};

// from DeviceAttestationCredsExample.cpp
const uint8_t kCd[] = {
    0x30, 0x82, 0x02, 0x19, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
    0x01, 0x07, 0x02, 0xa0, 0x82, 0x02, 0x0a, 0x30, 0x82, 0x02, 0x06, 0x02,
    0x01, 0x03, 0x31, 0x0d, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
    0x65, 0x03, 0x04, 0x02, 0x01, 0x30, 0x82, 0x01, 0x70, 0x06, 0x09, 0x2a,
    0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01, 0xa0, 0x82, 0x01, 0x61,
    0x04, 0x82, 0x01, 0x5d, 0x15, 0x24, 0x00, 0x01, 0x25, 0x01, 0xf2, 0xff,
    0x36, 0x02, 0x05, 0x00, 0x80, 0x05, 0x01, 0x80, 0x05, 0x02, 0x80, 0x05,
    0x03, 0x80, 0x05, 0x04, 0x80, 0x05, 0x05, 0x80, 0x05, 0x06, 0x80, 0x05,
    0x07, 0x80, 0x05, 0x08, 0x80, 0x05, 0x09, 0x80, 0x05, 0x0a, 0x80, 0x05,
    0x0b, 0x80, 0x05, 0x0c, 0x80, 0x05, 0x0d, 0x80, 0x05, 0x0e, 0x80, 0x05,
    0x0f, 0x80, 0x05, 0x10, 0x80, 0x05, 0x11, 0x80, 0x05, 0x12, 0x80, 0x05,
    0x13, 0x80, 0x05, 0x14, 0x80, 0x05, 0x15, 0x80, 0x05, 0x16, 0x80, 0x05,
    0x17, 0x80, 0x05, 0x18, 0x80, 0x05, 0x19, 0x80, 0x05, 0x1a, 0x80, 0x05,
    0x1b, 0x80, 0x05, 0x1c, 0x80, 0x05, 0x1d, 0x80, 0x05, 0x1e, 0x80, 0x05,
    0x1f, 0x80, 0x05, 0x20, 0x80, 0x05, 0x21, 0x80, 0x05, 0x22, 0x80, 0x05,
    0x23, 0x80, 0x05, 0x24, 0x80, 0x05, 0x25, 0x80, 0x05, 0x26, 0x80, 0x05,
    0x27, 0x80, 0x05, 0x28, 0x80, 0x05, 0x29, 0x80, 0x05, 0x2a, 0x80, 0x05,
    0x2b, 0x80, 0x05, 0x2c, 0x80, 0x05, 0x2d, 0x80, 0x05, 0x2e, 0x80, 0x05,
    0x2f, 0x80, 0x05, 0x30, 0x80, 0x05, 0x31, 0x80, 0x05, 0x32, 0x80, 0x05,
    0x33, 0x80, 0x05, 0x34, 0x80, 0x05, 0x35, 0x80, 0x05, 0x36, 0x80, 0x05,
    0x37, 0x80, 0x05, 0x38, 0x80, 0x05, 0x39, 0x80, 0x05, 0x3a, 0x80, 0x05,
    0x3b, 0x80, 0x05, 0x3c, 0x80, 0x05, 0x3d, 0x80, 0x05, 0x3e, 0x80, 0x05,
    0x3f, 0x80, 0x05, 0x40, 0x80, 0x05, 0x41, 0x80, 0x05, 0x42, 0x80, 0x05,
    0x43, 0x80, 0x05, 0x44, 0x80, 0x05, 0x45, 0x80, 0x05, 0x46, 0x80, 0x05,
    0x47, 0x80, 0x05, 0x48, 0x80, 0x05, 0x49, 0x80, 0x05, 0x4a, 0x80, 0x05,
    0x4b, 0x80, 0x05, 0x4c, 0x80, 0x05, 0x4d, 0x80, 0x05, 0x4e, 0x80, 0x05,
    0x4f, 0x80, 0x05, 0x50, 0x80, 0x05, 0x51, 0x80, 0x05, 0x52, 0x80, 0x05,
    0x53, 0x80, 0x05, 0x54, 0x80, 0x05, 0x55, 0x80, 0x05, 0x56, 0x80, 0x05,
    0x57, 0x80, 0x05, 0x58, 0x80, 0x05, 0x59, 0x80, 0x05, 0x5a, 0x80, 0x05,
    0x5b, 0x80, 0x05, 0x5c, 0x80, 0x05, 0x5d, 0x80, 0x05, 0x5e, 0x80, 0x05,
    0x5f, 0x80, 0x05, 0x60, 0x80, 0x05, 0x61, 0x80, 0x05, 0x62, 0x80, 0x05,
    0x63, 0x80, 0x18, 0x24, 0x03, 0x16, 0x2c, 0x04, 0x13, 0x43, 0x53, 0x41,
    0x30, 0x30, 0x30, 0x30, 0x30, 0x53, 0x57, 0x43, 0x30, 0x30, 0x30, 0x30,
    0x30, 0x2d, 0x30, 0x30, 0x24, 0x05, 0x00, 0x24, 0x06, 0x00, 0x24, 0x07,
    0x01, 0x24, 0x08, 0x00, 0x18, 0x31, 0x7e, 0x30, 0x7c, 0x02, 0x01, 0x03,
    0x80, 0x14, 0x62, 0xfa, 0x82, 0x33, 0x59, 0xac, 0xfa, 0xa9, 0x96, 0x3e,
    0x1c, 0xfa, 0x14, 0x0a, 0xdd, 0xf5, 0x04, 0xf3, 0x71, 0x60, 0x30, 0x0b,
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x30,
    0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x04,
    0x48, 0x30, 0x46, 0x02, 0x21, 0x00, 0x8d, 0xed, 0x3d, 0xdd, 0xbb, 0x6f,
    0x3c, 0x6d, 0xca, 0xc7, 0xb5, 0x75, 0x14, 0xc5, 0x8e, 0x69, 0x4a, 0xea,
    0xd4, 0xc2, 0xc8, 0x2f, 0x9b, 0x46, 0x2b, 0x73, 0xeb, 0x00, 0x3a, 0x60,
    0x41, 0xf2, 0x02, 0x21, 0x00, 0xbd, 0x95, 0xe7, 0x9e, 0xe3, 0x8c, 0x07,
    0x90, 0xd6, 0x9b, 0xaa, 0x45, 0x3b, 0xfc, 0x3c, 0x74, 0x96, 0x6c, 0x79,
    0x4f, 0x1c, 0x4d, 0xd7, 0x5d, 0x15, 0x03, 0x24, 0xd8, 0xa5, 0xca, 0x82,
    0x3d};
